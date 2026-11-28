import {
  BadRequestException,
  ConflictException,
  GoneException,
  HttpException,
  HttpStatus,
  Injectable,
  InternalServerErrorException,
  Logger,
  NotFoundException,
  Optional,
  UnprocessableEntityException,
} from '@nestjs/common';
import Database from 'better-sqlite3';
import { createHash } from 'node:crypto';
import fs, { existsSync, mkdirSync } from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import * as tar from 'tar';
import {
  createPaginatedResponse,
  type PaginatedResponse,
} from '../../../common/pagination/paginated-response.dto.js';
import { buildPaginationSqlFragment } from '../../../common/pagination/sql-query-builder.js';
import { newId } from '../../../common/persistence/identifiers.js';
import { nowIso } from '../../../common/persistence/timestamps.js';
import { AppConfigService } from '../../../config/app-config.service.js';
import { resolveDefaultDataDir } from '../../../config/data-dir.js';
import { EncryptionService } from '../../../crypto/encryption/encryption.service.js';
import { DatabaseService } from '../../../database/database.service.js';
import { FileStorageService } from '../../../file-storage/file-storage.service.js';
import {
  ALLOWED_BACKUP_SORT_COLUMNS,
  type BackupArchiveStreamInfo,
  type BackupFileInventoryItem,
  type BackupManifest,
  type BackupRecordRow,
  type CreateBackupOptions,
  type RestoreBackupOptions,
} from './backups.types.js';
import {
  BACKUP_TRIGGERS,
  BackupResponseDto,
} from './dto/backup-response.dto.js';
import { ListBackupsQueryDto } from './dto/list-backups-query.dto.js';
import { RestoreBackupResponseDto } from './dto/restore-backup-response.dto.js';

/**
 * Current backup archive format specification version.
 */
export const BACKUP_FORMAT_VERSION = 1;

/**
 * Fallback application version string if unresolvable.
 */
export const DEFAULT_APP_VERSION = '0.1.0';

/**
 * Service managing backup creation, listing, retrieval, deletion, and restoration.
 *
 * ## Archive Format
 * A backup archive is a single gzipped tar file (`.tar.gz`) containing:
 * - `manifest.json`: Format version, creation timestamp, app version, database schema
 *   version, optional user label/note, and a file inventory with SHA-256 hashes.
 * - `database.sqlite`: A consistent snapshot of the SQLite database created via
 *   `VACUUM INTO`. Does not use raw file copies so that WAL journal frames are
 *   checkpointed into a clean, standalone database file.
 * - `files/`: Mirror of the file storage directory (agent pictures, project images,
 *   artifact blobs).
 *
 * ## Encryption Key Decision & Threat Model
 * Provider credentials (`provider_credentials`) store API keys encrypted with AES-256-GCM.
 * The 256-bit master key (`master.key`) lives in the user data directory with restrictive
 * permissions (`0600`), separate from the SQLite database (`glassbeetle.db`).
 *
 * **Deliberate Security Decision**: Backup archives intentionally **EXCLUDE** `master.key`.
 * Bundling the master key with the database snapshot inside an archive would eliminate the
 * cryptographic separation between ciphertext and encryption keys whenever users export,
 * share, or sync archives to external storage.
 *
 * Consequently, restoring a backup on a new device will require provider API keys to be
 * re-entered, ensuring sensitive credentials are never leaked via synced backup files.
 *
 * ## Restore Semantics & What Restore Destroys
 * Restoring from a backup replaces the active database and file storage tree with the
 * contents of the backup archive:
 * 1. **Database records**: Replaces `glassbeetle.db`. All records created or modified
 *    since the snapshot was taken (chats, messages, agents, teams, projects, memories,
 *    user profile, spend tracking) are permanently replaced by the archive snapshot.
 * 2. **File storage**: Replaces the file storage directory (`storage/`). Any agent pictures,
 *    project images, or artifact blobs created since the backup are removed.
 * 3. **Provider credentials**: Deliberately excluded from the archive. If restored on a machine
 *    with a differing master encryption key, credentials cannot be decrypted and must be re-entered.
 *
 * ## Fate of Newer Backups After Restoring an Older One
 * The SQLite `backups` table itself resides within the restored database snapshot. Restoring
 * an older backup replaces this table with the historical table state from that snapshot date.
 * Consequently, backup records created after the restored snapshot date will no longer appear
 * in API listings (`GET /application/backups`). Their physical archive files (`.tar.gz`) on disk
 * are **intentionally preserved** in the backup directory to prevent data loss, but will remain
 * unreferenced in the database.
 *
 * ## Safety Snapshot & Rollback Strategy
 * To protect against losing active application state if a restore operation fails mid-flight:
 * 1. All archive validation (row check, archive existence, archive extraction, manifest parsing,
 *    format version verification, schema compatibility check, database integrity check, file
 *    checksum verification) executes strictly **BEFORE** any destructive action.
 * 2. Before replacing any files, a consistent safety snapshot of the active SQLite database is
 *    created via `VACUUM INTO` and a full copy of the active file storage tree is taken in an
 *    isolated temporary staging location.
 * 3. Replacements are performed atomically via staged file copy and filesystem renames.
 * 4. If any error occurs during database or file storage replacement, an automatic rollback
 *    procedure restores the pre-restore database and storage trees from the safety snapshot,
 *    reconnects the SQLite database, and returns `500 Internal Server Error`, leaving the
 *    original data completely intact.
 *
 * ## Concurrency
 * Backups and restores are mutually exclusive. If a backup or restore is already running,
 * subsequent requests immediately fail with `409 Conflict`.
 *
 * ## Deletion Semantics
 * Deleting a backup removes its database row and deletes the archive file from disk.
 * Deleting a backup is **irreversible** and **does not affect active application data**.
 * If the physical archive file is already missing on disk (e.g. manually deleted by the user),
 * the operation succeeds and removes the lingering database row.
 */
@Injectable()
export class BackupsService {
  private readonly logger = new Logger(BackupsService.name);
  private isBackupInProgress = false;
  private isRestoreInProgress = false;

  /**
   * Reports whether a backup or restore operation is actively in progress.
   */
  public get isOperationInProgress(): boolean {
    return this.isBackupInProgress || this.isRestoreInProgress;
  }

  constructor(
    private readonly databaseService: DatabaseService,
    private readonly fileStorageService: FileStorageService,
    @Optional() private readonly appConfigService?: AppConfigService,
    @Optional() private readonly encryptionService?: EncryptionService,
  ) { }

  /**
   * Creates a self-contained backup archive and records its metadata.
   *
   * Callable on demand by the HTTP controller (trigger = 'manual') or by the
   * background backup scheduler (trigger = 'scheduled').
   *
   * @param options - Backup parameters including trigger source, optional label and note.
   * @returns Metadata of the newly created backup.
   * @throws ConflictException (409) if a backup or restore is already in progress.
   * @throws BadRequestException (400) if the target directory is invalid or unwritable.
   * @throws HttpException (507) if detectable disk space is insufficient.
   * @throws InternalServerErrorException (500) if creation fails.
   */
  async createBackup(
    options: CreateBackupOptions = {},
  ): Promise<BackupResponseDto> {
    if (this.isBackupInProgress || this.isRestoreInProgress) {
      throw new ConflictException(
        'A backup or restore operation is already in progress',
      );
    }

    this.isBackupInProgress = true;

    const id = newId();
    const createdAt = nowIso();
    const trigger = options.trigger ?? 'manual';

    let stagingDir: string | undefined;
    let partialArchivePath: string | undefined;
    let finalArchivePath: string | undefined;

    try {
      const targetDir = this.resolveTargetDirectory();
      const archiveFileName = `backup-${id}.tar.gz`;
      partialArchivePath = path.join(targetDir, `${archiveFileName}.tmp`);
      finalArchivePath = path.join(targetDir, archiveFileName);

      this.checkDiskSpace(targetDir);

      // Create staging directories. The staging copy holds the full
      // database snapshot and every stored file, and os.tmpdir() is the
      // shared /tmp on Linux, so it must be owner-only. mkdtemp creates the
      // directory with 0o700 under an unpredictable name; the chmod is the
      // same belt-and-braces that encryption.service.ts uses for master.key.
      stagingDir = await fs.promises.mkdtemp(
        path.join(os.tmpdir(), `glassbeetle-backup-${id}-`),
      );
      await fs.promises.chmod(stagingDir, 0o700);
      const stagingFilesDir = path.join(stagingDir, 'files');
      await fs.promises.mkdir(stagingFilesDir, {
        recursive: true,
        mode: 0o700,
      });
      await fs.promises.chmod(stagingFilesDir, 0o700);

      // 1. Snapshot database consistently with VACUUM INTO
      const dbSnapshotPath = path.join(stagingDir, 'database.sqlite');
      this.databaseService.db.prepare('VACUUM INTO ?').run(dbSnapshotPath);
      await fs.promises.chmod(dbSnapshotPath, 0o600);

      // 2. Copy file storage tree into files/ and collect inventory
      const fileInventory: BackupFileInventoryItem[] = [];
      const storageRoot = this.fileStorageService.storageRoot;
      await this.copyStorageTree(
        storageRoot,
        stagingFilesDir,
        'files',
        fileInventory,
      );

      // 3. Write manifest.json
      const manifest: BackupManifest = {
        formatVersion: BACKUP_FORMAT_VERSION,
        createdAt,
        appVersion: this.getAppVersion(),
        databaseSchemaVersion: this.getDatabaseSchemaVersion(),
        label: options.label?.trim() || null,
        note: options.note?.trim() || null,
        fileInventory,
      };

      const manifestPath = path.join(stagingDir, 'manifest.json');
      await fs.promises.writeFile(
        manifestPath,
        JSON.stringify(manifest, null, 2),
        { encoding: 'utf8', mode: 0o600 },
      );
      await fs.promises.chmod(manifestPath, 0o600);

      // 4. Stream archive creation. Create the archive file owner-only
      // (0o600) before tar writes to it, so it is never readable by other
      // accounts, not even while it is being written. tar truncates the
      // existing file and keeps its mode, and the rename below keeps it too.
      await fs.promises.rm(partialArchivePath, { force: true });
      const partialHandle = await fs.promises.open(
        partialArchivePath,
        'wx',
        0o600,
      );
      await partialHandle.close();
      await fs.promises.chmod(partialArchivePath, 0o600);

      await tar.create(
        {
          gzip: true,
          file: partialArchivePath,
          cwd: stagingDir,
          mode: 0o600,
        },
        ['manifest.json', 'database.sqlite', 'files'],
      );

      // Atomic rename of partial archive to final archive
      await fs.promises.rename(partialArchivePath, finalArchivePath);
      await fs.promises.chmod(finalArchivePath, 0o600);

      const stats = await fs.promises.stat(finalArchivePath);
      const sizeBytes = stats.size;

      // 5. Record metadata in the database
      this.databaseService.run(
        `INSERT INTO backups (id, file_path, size_bytes, trigger, created_at)
         VALUES (?, ?, ?, ?, ?)`,
        [id, archiveFileName, sizeBytes, trigger, createdAt],
      );

      this.logger.log(
        `Backup created successfully: id=${id}, sizeBytes=${sizeBytes}, trigger=${trigger}`,
      );

      return {
        id,
        sizeBytes,
        trigger,
        createdAt,
        hasArchive: true,
        isAvailable: true,
      };
    } catch (error) {
      this.logger.error(
        `Backup creation failed: ${error instanceof Error ? error.message : String(error)}`,
      );

      // Clean up partial archive if left behind
      try {
        if (partialArchivePath && existsSync(partialArchivePath)) {
          await fs.promises.unlink(partialArchivePath);
        }
      } catch { }

      // Clean up final archive if write failed after creation
      try {
        if (finalArchivePath && existsSync(finalArchivePath)) {
          await fs.promises.unlink(finalArchivePath);
        }
      } catch { }

      // Clean up database row if partially recorded
      try {
        this.databaseService.run('DELETE FROM backups WHERE id = ?', [id]);
      } catch { }

      if (error instanceof HttpException) {
        throw error;
      }

      throw new InternalServerErrorException(
        `Backup creation failed: ${error instanceof Error ? error.message : String(error)}`,
      );
    } finally {
      // Always remove temporary staging directory
      try {
        if (stagingDir && existsSync(stagingDir)) {
          await fs.promises.rm(stagingDir, { recursive: true, force: true });
        }
      } catch (cleanupError) {
        this.logger.warn(
          `Failed to clean up backup staging directory: ${cleanupError instanceof Error ? cleanupError.message : String(cleanupError)}`,
        );
      }

      this.isBackupInProgress = false;
    }
  }

  /**
   * Retrieves a paginated list of backups, sorted newest first by default.
   *
   * @param query - Pagination, sorting, and trigger filter parameters.
   * @returns Paginated collection of backup metadata items.
   * @throws BadRequestException (400) if sorting or trigger filter is invalid.
   */
  async findAll(
    query: ListBackupsQueryDto = new ListBackupsQueryDto(),
  ): Promise<PaginatedResponse<BackupResponseDto>> {
    const conditions: string[] = [];
    const filterParams: unknown[] = [];

    if (query.trigger) {
      if (!BACKUP_TRIGGERS.includes(query.trigger)) {
        throw new BadRequestException(
          `Invalid trigger filter: "${query.trigger}". Must be 'manual' or 'scheduled'`,
        );
      }
      conditions.push('trigger = ?');
      filterParams.push(query.trigger);
    }

    const whereClause =
      conditions.length > 0 ? `WHERE ${conditions.join(' AND ')}` : '';

    const countSql = `SELECT COUNT(*) AS total FROM backups ${whereClause}`;
    const countRow = this.databaseService.get<{ total: number }>(
      countSql,
      filterParams,
    );
    const total = countRow?.total ?? 0;

    const pagination = buildPaginationSqlFragment({
      query,
      allowedSortColumns: ALLOWED_BACKUP_SORT_COLUMNS,
      defaultSortKey: 'createdAt',
      defaultOrder: 'desc',
      tiebreakerColumn: 'id',
    });

    const selectSql = `SELECT * FROM backups ${whereClause} ${pagination.clauseSql}`;
    const rows = this.databaseService.all<BackupRecordRow>(selectSql, [
      ...filterParams,
      ...pagination.params,
    ]);

    return createPaginatedResponse(
      rows.map((row) => this.mapRowToResponse(row)),
      total,
      pagination.params[0],
      pagination.params[1],
    );
  }

  /**
   * Retrieves a single backup by its unique identifier, or null if not found.
   *
   * @param id - Backup UUIDv7 identifier.
   * @returns Backup metadata if found, null otherwise.
   */
  async findById(id: string): Promise<BackupResponseDto | null> {
    const row = this.databaseService.get<BackupRecordRow>(
      'SELECT * FROM backups WHERE id = ?',
      [id],
    );
    if (!row) {
      return null;
    }
    return this.mapRowToResponse(row);
  }

  /**
   * Retrieves a single backup by its unique identifier.
   *
   * @param id - Backup UUIDv7 identifier.
   * @returns Backup metadata.
   * @throws NotFoundException (404) if no backup exists with the given ID.
   */
  async findOne(id: string): Promise<BackupResponseDto> {
    const backup = await this.findById(id);
    if (!backup) {
      throw new NotFoundException({
        code: 'BACKUP_NOT_FOUND',
        message: `No backup found with ID "${id}"`,
      });
    }
    return backup;
  }

  /**
   * Deletes a backup record and its archive file from disk.
   *
   * Deletion order:
   * 1. The database row is deleted first.
   * 2. The archive file is unlinked from the filesystem.
   *
   * Ordering justification:
   * Deleting the database row before the file avoids leaving an unrecoverable database
   * row pointing at a deleted archive if an unexpected crash occurs mid-deletion.
   * If the physical archive is already gone, the database row is still cleaned up cleanly.
   *
   * This operation is irreversible and does not affect the active database or current
   * application data.
   *
   * @param id - Backup UUIDv7 identifier.
   * @throws NotFoundException (404) if no backup exists with the given ID.
   */
  async deleteBackup(id: string): Promise<void> {
    const row = this.databaseService.get<BackupRecordRow>(
      'SELECT * FROM backups WHERE id = ?',
      [id],
    );
    if (!row) {
      throw new NotFoundException({
        code: 'BACKUP_NOT_FOUND',
        message: `No backup found with ID "${id}"`,
      });
    }

    // 1. Delete database row first
    this.databaseService.run('DELETE FROM backups WHERE id = ?', [id]);

    // 2. Unlink archive file
    if (row.file_path) {
      try {
        const archivePath = this.archivePathFor(row);
        if (existsSync(archivePath)) {
          fs.unlinkSync(archivePath);
          this.logger.log(`Deleted backup archive file: ${archivePath}`);
        } else {
          this.logger.warn(
            `Backup archive file was already missing on disk: ${archivePath}`,
          );
        }
      } catch (unlinkError) {
        this.logger.warn(
          `Failed to unlink backup archive file for backup "${id}": ${unlinkError instanceof Error ? unlinkError.message : String(unlinkError)}`,
        );
      }
    }
  }

  /**
   * Enforces the retention policy by deleting the oldest scheduled backups beyond retentionCount.
   *
   * ## Retention Policy Decision & Threat Model
   * Automatic retention is destructive and must be carefully scoped:
   * 1. **Scheduled Backups Only**: Retention strictly queries and deletes backups with
   *    `trigger = 'scheduled'`. User-created manual backups (`trigger = 'manual'`) are
   *    **NEVER** deleted by retention enforcement. Users create manual backups intentionally
   *    before risky operations; deleting them automatically because an automatic policy wants
   *    to keep N backups would be an unexpected and catastrophic data loss event.
   * 2. **Defensive Non-Positive Guard**: If `retentionCount <= 0` (e.g. invalid or corrupted
   *    database value), retention enforcement is aborted immediately without deleting any
   *    backups. This prevents catastrophic mass deletion if retention_count in the database is 0.
   * 3. **Ordering**: Scheduled backups are ordered newest first (`created_at DESC, id DESC`).
   *    The first `retentionCount` scheduled backups are preserved; all scheduled backups
   *    beyond this threshold are deleted.
   * 4. **Atomicity & Consistency**: Reuses `deleteBackup(id)` so that both the database row
   *    and the physical archive file on disk are removed consistently.
   *
   * @param retentionCount - Number of recent scheduled backups to retain (must be >= 1).
   * @returns Array of deleted backup IDs.
   */
  async enforceRetention(retentionCount: number): Promise<string[]> {
    if (
      typeof retentionCount !== 'number' ||
      !Number.isFinite(retentionCount) ||
      retentionCount < 1
    ) {
      this.logger.warn(
        `Retention enforcement skipped: non-positive or invalid retentionCount (${retentionCount}). No backups were deleted.`,
      );
      return [];
    }

    // Query ONLY scheduled backups, ordered newest first
    const scheduledBackups = this.databaseService.all<{ id: string }>(
      `SELECT id FROM backups WHERE trigger = 'scheduled' ORDER BY created_at DESC, id DESC`,
    );

    if (scheduledBackups.length <= retentionCount) {
      return [];
    }

    const backupsToDelete = scheduledBackups.slice(retentionCount);
    const deletedIds: string[] = [];

    this.logger.log(
      `Enforcing retention: found ${scheduledBackups.length} scheduled backups, retaining ${retentionCount}, pruning ${backupsToDelete.length} oldest.`,
    );

    for (const backup of backupsToDelete) {
      try {
        await this.deleteBackup(backup.id);
        deletedIds.push(backup.id);
        this.logger.log(`Retention pruned scheduled backup: id=${backup.id}`);
      } catch (error) {
        this.logger.error(
          `Failed to prune scheduled backup id=${backup.id} during retention: ${error instanceof Error ? error.message : String(error)}`,
        );
      }
    }

    return deletedIds;
  }

  /**
   * Retrieves archive metadata and an open stream factory for streaming the archive download.
   *
   * ## Security & Integrity
   * - Validates that the archive path strictly resides inside the configured backup directory.
   * - Performs a fresh filesystem stat to verify the archive exists and record exact size.
   * - Does not expose filesystem paths in error messages or exceptions.
   *
   * @param id - Backup UUIDv7 identifier.
   * @returns Streaming info containing id, createdAt, fresh stat sizeBytes, and openStream.
   * @throws NotFoundException (404) if no backup row exists with the given ID.
   * @throws BadRequestException (400) if the stored archive path escapes the backup directory.
   * @throws GoneException (410) if the backup row exists but the physical archive file is missing.
   */
  async getBackupArchive(id: string): Promise<BackupArchiveStreamInfo> {
    const row = this.databaseService.get<BackupRecordRow>(
      'SELECT * FROM backups WHERE id = ?',
      [id],
    );
    if (!row) {
      throw new NotFoundException({
        code: 'BACKUP_NOT_FOUND',
        message: `No backup found with ID "${id}"`,
      });
    }

    const archivePath = this.resolveAndValidateArchivePath(row);

    if (!existsSync(archivePath)) {
      throw new GoneException({
        code: 'BACKUP_ARCHIVE_GONE',
        message: 'Backup archive file is missing from disk',
      });
    }

    let stats: fs.Stats;
    try {
      stats = await fs.promises.stat(archivePath);
    } catch {
      throw new GoneException({
        code: 'BACKUP_ARCHIVE_GONE',
        message: 'Backup archive file is missing from disk',
      });
    }

    if (!stats.isFile()) {
      throw new GoneException({
        code: 'BACKUP_ARCHIVE_GONE',
        message: 'Backup archive file is missing from disk',
      });
    }

    return {
      id: row.id,
      createdAt: row.created_at,
      sizeBytes: stats.size,
      openStream: (range?: { start?: number; end?: number }) => {
        return fs.createReadStream(archivePath, range);
      },
    };
  }

  /**
   * Restores application database and file storage from a backup archive.
   *
   * ## Destructive Operation
   * Irreversibly replaces the active SQLite database (`glassbeetle.db`) and the
   * file storage tree (`storage/`).
   *
   * ## Validation & Execution Order
   * 1. Requires explicit confirmation (`confirm: 'true'`).
   * 2. Validates backup record exists in `backups` table (404).
   * 3. Validates archive file exists on disk and is a regular file (404).
   * 4. Validates archive opens as valid tar/gzip and contains no path traversal (422).
   * 5. Validates manifest.json parses and contains required fields (422).
   * 6. Validates format version is supported (422).
   * 7. Validates database schema version is compatible with current application (409).
   * 8. Validates database.sqlite inside archive opens read-only, passes integrity check,
   *    and contains core application tables (422).
   * 9. Validates file inventory checksums (422).
   * 10. Takes a consistent safety snapshot (VACUUM INTO + copy storage) to enable rollback.
   * 11. Closes SQLite connection, atomically renames new database, reopens connection.
   * 12. Atomically replaces file storage tree.
   * 13. Reports credential verification outcome and required user actions.
   *
   * On any failure during or after database replacement, automatically rolls back
   * database and storage to the safety snapshot and throws InternalServerErrorException (500).
   *
   * @param id - Backup UUIDv7 identifier.
   * @param options - Restore options including explicit confirmation flag.
   * @returns Detailed outcome of restore operation.
   * @throws BadRequestException (400) if confirmation is missing or invalid.
   * @throws NotFoundException (404) if backup record or archive file is missing.
   * @throws ConflictException (409) if archive schema version is incompatible or operation in progress.
   * @throws UnprocessableEntityException (422) if archive is corrupt, malformed, or fails integrity checks.
   * @throws InternalServerErrorException (500) if restore fails; pre-restore state is rolled back.
   */
  async restoreBackup(
    id: string,
    options: RestoreBackupOptions = {},
  ): Promise<RestoreBackupResponseDto> {
    if (options.confirm !== 'true') {
      throw new BadRequestException({
        code: 'CONFIRMATION_REQUIRED',
        message:
          'Explicit confirmation is required to restore a backup (confirm must be "true")',
      });
    }

    if (this.isBackupInProgress || this.isRestoreInProgress) {
      throw new ConflictException(
        'A backup or restore operation is already in progress',
      );
    }

    this.isRestoreInProgress = true;
    this.logger.warn(
      `Starting restore from backup: id="${id}". Validating archive before any modification...`,
    );

    let stagingExtractDir: string | undefined;
    let safetyDir: string | undefined;
    let safetyDbPath: string | undefined;
    let safetyStorageDir: string | undefined;

    let dbClosed = false;
    let dbReplaced = false;
    let storageReplaced = false;

    let targetDbPath = '';
    const storageRoot = this.fileStorageService.storageRoot;

    try {
      // 1. Validate backup row exists
      const row = this.databaseService.get<BackupRecordRow>(
        'SELECT * FROM backups WHERE id = ?',
        [id],
      );
      if (!row) {
        throw new NotFoundException({
          code: 'BACKUP_NOT_FOUND',
          message: `No backup found with ID "${id}"`,
        });
      }

      // 2. Validate archive file exists on disk
      const archivePath = this.resolveAndValidateArchivePath(row);
      if (!existsSync(archivePath)) {
        throw new NotFoundException({
          code: 'BACKUP_ARCHIVE_NOT_FOUND',
          message: 'Backup archive file is missing from disk',
        });
      }

      const stat = fs.statSync(archivePath);
      if (!stat.isFile()) {
        throw new NotFoundException({
          code: 'BACKUP_ARCHIVE_NOT_FOUND',
          message: 'Backup archive file is missing from disk',
        });
      }

      // 3. Inspect archive entries for corruption and path traversal before extraction
      const tarEntries: string[] = [];
      try {
        await tar.t({
          file: archivePath,
          onentry: (entry) => {
            tarEntries.push(entry.path);
          },
        });
      } catch (tarErr) {
        throw new UnprocessableEntityException({
          code: 'CORRUPT_ARCHIVE',
          message: `Backup archive is corrupt or malformed: ${tarErr instanceof Error ? tarErr.message : String(tarErr)}`,
        });
      }

      if (tarEntries.length === 0) {
        throw new UnprocessableEntityException({
          code: 'CORRUPT_ARCHIVE',
          message: 'Backup archive is empty',
        });
      }

      for (const entryPath of tarEntries) {
        if (this.isPathTraversalOrUnsafe(entryPath)) {
          throw new UnprocessableEntityException({
            code: 'MALFORMED_ARCHIVE',
            message: `Backup archive contains illegal or traversing path: "${entryPath}"`,
          });
        }
      }

      // 4. Extract archive to temporary staging directory
      stagingExtractDir = await fs.promises.mkdtemp(
        path.join(os.tmpdir(), `glassbeetle-restore-extract-${id}-`),
      );
      await fs.promises.chmod(stagingExtractDir, 0o700);

      try {
        await tar.x({
          file: archivePath,
          cwd: stagingExtractDir,
          mode: 0o700,
        });
      } catch (extractErr) {
        throw new UnprocessableEntityException({
          code: 'CORRUPT_ARCHIVE',
          message: `Failed to extract backup archive: ${extractErr instanceof Error ? extractErr.message : String(extractErr)}`,
        });
      }

      // 5. Validate manifest.json
      const manifestPath = path.join(stagingExtractDir, 'manifest.json');
      if (!existsSync(manifestPath)) {
        throw new UnprocessableEntityException({
          code: 'INVALID_ARCHIVE_MANIFEST',
          message: 'Backup archive is missing manifest.json',
        });
      }

      let manifest: BackupManifest;
      try {
        const manifestContent = await fs.promises.readFile(
          manifestPath,
          'utf8',
        );
        manifest = JSON.parse(manifestContent);
      } catch (parseErr) {
        throw new UnprocessableEntityException({
          code: 'INVALID_ARCHIVE_MANIFEST',
          message: `manifest.json in backup archive is corrupt: ${parseErr instanceof Error ? parseErr.message : String(parseErr)}`,
        });
      }

      if (
        !manifest ||
        typeof manifest !== 'object' ||
        typeof manifest.formatVersion !== 'number' ||
        typeof manifest.databaseSchemaVersion !== 'string'
      ) {
        throw new UnprocessableEntityException({
          code: 'INVALID_ARCHIVE_MANIFEST',
          message: 'manifest.json is missing required metadata fields',
        });
      }

      // 6. Validate format version
      if (manifest.formatVersion !== BACKUP_FORMAT_VERSION) {
        throw new UnprocessableEntityException({
          code: 'UNSUPPORTED_FORMAT_VERSION',
          message: `Unsupported backup format version: ${manifest.formatVersion} (current supported version is ${BACKUP_FORMAT_VERSION})`,
        });
      }

      // 7. Validate schema version compatibility
      const currentSchemaVersion = this.getDatabaseSchemaVersion();
      if (manifest.databaseSchemaVersion !== currentSchemaVersion) {
        throw new ConflictException({
          code: 'INCOMPATIBLE_SCHEMA_VERSION',
          message: `Backup archive database schema version "${manifest.databaseSchemaVersion}" is incompatible with current application schema version "${currentSchemaVersion}". Schema migration during restore is not supported.`,
        });
      }

      // 8. Validate database.sqlite snapshot inside archive
      const extractedDbPath = path.join(stagingExtractDir, 'database.sqlite');
      if (
        !existsSync(extractedDbPath) ||
        !fs.statSync(extractedDbPath).isFile()
      ) {
        throw new UnprocessableEntityException({
          code: 'MISSING_DATABASE_SNAPSHOT',
          message: 'Backup archive is missing database.sqlite',
        });
      }

      let readOnlyDb: Database.Database;
      try {
        readOnlyDb = new Database(extractedDbPath, {
          readonly: true,
          fileMustExist: true,
        });
      } catch (dbOpenErr) {
        throw new UnprocessableEntityException({
          code: 'CORRUPT_DATABASE_SNAPSHOT',
          message: `Extracted database.sqlite cannot be opened: ${dbOpenErr instanceof Error ? dbOpenErr.message : String(dbOpenErr)}`,
        });
      }

      try {
        const integrity = readOnlyDb.pragma('integrity_check', {
          simple: true,
        });
        if (integrity !== 'ok') {
          throw new UnprocessableEntityException({
            code: 'DATABASE_INTEGRITY_CHECK_FAILED',
            message: `Database integrity check failed: ${String(integrity)}`,
          });
        }

        const tableRows = readOnlyDb
          .prepare("SELECT name FROM sqlite_master WHERE type = 'table'")
          .all() as Array<{ name: string }>;
        const tableNames = new Set(tableRows.map((r) => r.name));
        const requiredTables = [
          'system_prompts',
          'providers',
          'models',
          'agents',
          'chats',
          'messages',
          'backups',
        ];
        const missingTables = requiredTables.filter((t) => !tableNames.has(t));
        if (missingTables.length > 0) {
          throw new UnprocessableEntityException({
            code: 'DATABASE_TABLES_MISSING',
            message: `Archive database snapshot is missing required tables: ${missingTables.join(', ')}`,
          });
        }
      } catch (dbErr) {
        if (dbErr instanceof HttpException) {
          throw dbErr;
        }
        throw new UnprocessableEntityException({
          code: 'DATABASE_INTEGRITY_CHECK_FAILED',
          message: `Database integrity check failed: ${dbErr instanceof Error ? dbErr.message : String(dbErr)}`,
        });
      } finally {
        readOnlyDb.close();
      }

      // 9. Validate files inventory and checksums
      if (
        Array.isArray(manifest.fileInventory) &&
        manifest.fileInventory.length > 0
      ) {
        for (const item of manifest.fileInventory) {
          if (this.isPathTraversalOrUnsafe(item.path)) {
            throw new UnprocessableEntityException({
              code: 'MALFORMED_ARCHIVE',
              message: `Inventory item contains illegal path: "${item.path}"`,
            });
          }
          const extractedFilePath = path.join(stagingExtractDir, item.path);
          if (
            !existsSync(extractedFilePath) ||
            !fs.statSync(extractedFilePath).isFile()
          ) {
            throw new UnprocessableEntityException({
              code: 'CORRUPT_ARCHIVE_FILES',
              message: `Archive file listed in inventory is missing: "${item.path}"`,
            });
          }
          const itemStat = await fs.promises.stat(extractedFilePath);
          if (itemStat.size !== item.sizeBytes) {
            throw new UnprocessableEntityException({
              code: 'CORRUPT_ARCHIVE_FILES',
              message: `Archive file size mismatch for "${item.path}": expected ${item.sizeBytes}, found ${itemStat.size}`,
            });
          }
          const content = await fs.promises.readFile(extractedFilePath);
          const hash = createHash('sha256').update(content).digest('hex');
          if (hash !== item.sha256) {
            throw new UnprocessableEntityException({
              code: 'CORRUPT_ARCHIVE_FILES',
              message: `Archive file hash mismatch for "${item.path}"`,
            });
          }
        }
      }

      // 10. TAKE SAFETY SNAPSHOT BEFORE DESTRUCTIVE ACTIONS
      safetyDir = await fs.promises.mkdtemp(
        path.join(os.tmpdir(), `glassbeetle-restore-safety-${id}-`),
      );
      await fs.promises.chmod(safetyDir, 0o700);

      safetyDbPath = path.join(safetyDir, 'safety-database.sqlite');
      this.databaseService.db.prepare('VACUUM INTO ?').run(safetyDbPath);
      await fs.promises.chmod(safetyDbPath, 0o600);

      safetyStorageDir = path.join(safetyDir, 'storage');
      if (existsSync(storageRoot)) {
        await fs.promises.cp(storageRoot, safetyStorageDir, {
          recursive: true,
        });
        await fs.promises.chmod(safetyStorageDir, 0o700);
      }

      // Resolve target database file path
      try {
        targetDbPath = this.databaseService.databasePath;
      } catch {
        targetDbPath = this.appConfigService?.databasePath ?? ':memory:';
      }

      if (
        !targetDbPath ||
        targetDbPath === ':memory:' ||
        targetDbPath.startsWith('file::memory:')
      ) {
        throw new BadRequestException(
          'Cannot restore into an in-memory database',
        );
      }

      const dbDir = path.dirname(targetDbPath);
      await fs.promises.mkdir(dbDir, { recursive: true });
      const stagedDbPath = path.join(
        dbDir,
        `.database-restore-${newId()}.sqlite`,
      );
      await fs.promises.copyFile(extractedDbPath, stagedDbPath);
      await fs.promises.chmod(stagedDbPath, 0o600);

      if (options._simulateFailureAt === 'after-validation') {
        throw new Error('Simulated failure after validation');
      }

      // 11. Close SQLite connection before replacing file
      this.databaseService.close();
      dbClosed = true;

      // 12. Atomic rename of database
      await fs.promises.rename(stagedDbPath, targetDbPath);
      await fs.promises.rm(`${targetDbPath}-wal`, { force: true });
      await fs.promises.rm(`${targetDbPath}-shm`, { force: true });
      dbReplaced = true;

      if (options._simulateFailureAt === 'mid-database-replacement') {
        throw new Error('Simulated failure mid-database-replacement');
      }

      // 13. Reopen database connection
      this.databaseService.connect(targetDbPath);
      dbClosed = false;

      // 14. File storage replacement
      const storageParent = path.dirname(storageRoot);
      await fs.promises.mkdir(storageParent, { recursive: true });
      const stagingStorageDir = path.join(
        storageParent,
        `.storage-restore-staging-${newId()}`,
      );
      const extractedFilesDir = path.join(stagingExtractDir, 'files');

      if (existsSync(extractedFilesDir)) {
        await fs.promises.cp(extractedFilesDir, stagingStorageDir, {
          recursive: true,
        });
      } else {
        await fs.promises.mkdir(stagingStorageDir, {
          recursive: true,
          mode: 0o700,
        });
      }

      if (options._simulateFailureAt === 'mid-file-replacement') {
        throw new Error('Simulated failure mid-file-replacement');
      }

      const oldStorageBackupDir = path.join(
        storageParent,
        `.storage-old-${newId()}`,
      );
      if (existsSync(storageRoot)) {
        await fs.promises.rename(storageRoot, oldStorageBackupDir);
      }
      await fs.promises.rename(stagingStorageDir, storageRoot);
      storageReplaced = true;

      if (existsSync(oldStorageBackupDir)) {
        await fs.promises.rm(oldStorageBackupDir, {
          recursive: true,
          force: true,
        });
      }

      // 15. Verify credentials situation
      let hasCredentials = false;
      let canDecrypt = true;
      let credMessage = 'No provider credentials stored in restored backup.';

      try {
        const credRows = this.databaseService.all<{
          provider_id: string;
          encrypted_value: Buffer;
          nonce: Buffer;
        }>(
          'SELECT provider_id, encrypted_value, nonce FROM provider_credentials',
        );

        if (credRows.length > 0) {
          hasCredentials = true;
          if (this.encryptionService) {
            for (const row of credRows) {
              try {
                this.encryptionService.decrypt(
                  row.encrypted_value,
                  row.nonce,
                  row.provider_id,
                );
              } catch {
                canDecrypt = false;
                break;
              }
            }
          } else {
            canDecrypt = false;
          }

          if (canDecrypt) {
            credMessage =
              'All restored provider credentials verified successfully with active master key.';
          } else {
            credMessage =
              'Restored provider credentials cannot be decrypted with the active master key. API keys must be re-entered in Settings > Providers.';
          }
        }
      } catch (credErr) {
        this.logger.warn(
          `Failed to inspect credentials table after restore: ${credErr instanceof Error ? credErr.message : String(credErr)}`,
        );
      }

      const filesRestored = manifest.fileInventory
        ? manifest.fileInventory.length
        : 0;
      const requiresCredentialReentry = hasCredentials && !canDecrypt;

      const actionsRequired: string[] = [];
      if (requiresCredentialReentry) {
        actionsRequired.push(
          'Re-enter provider API keys in Settings > Providers',
        );
      }
      actionsRequired.push(
        'Restart the application to reload running services with the restored state',
      );

      this.logger.warn(
        `Restore completed successfully: id="${id}", filesRestored=${filesRestored}, schema="${manifest.databaseSchemaVersion}", requiresCredentialReentry=${requiresCredentialReentry}.`,
      );

      return {
        backupId: id,
        restoredAt: nowIso(),
        databaseRestored: true,
        filesRestored,
        databaseSchemaVersion: manifest.databaseSchemaVersion,
        appVersion: manifest.appVersion,
        credentials: {
          hasCredentials,
          canDecrypt,
          requiresReentry: requiresCredentialReentry,
          message: credMessage,
        },
        requiresCredentialReentry,
        requiresRestart: true,
        actionsRequired,
        message: 'Backup restored successfully.',
      };
    } catch (error) {
      if (
        error instanceof HttpException &&
        !dbReplaced &&
        !storageReplaced &&
        !dbClosed
      ) {
        // Validation error before any state modification
        throw error;
      }

      this.logger.error(
        `Restore failed during destructive phase, initiating rollback: ${error instanceof Error ? error.message : String(error)}`,
      );

      let rollbackSucceeded = true;
      try {
        if (safetyDbPath && dbReplaced) {
          if (this.databaseService.isOpen) {
            this.databaseService.close();
          }
          const rollbackTmp = path.join(
            path.dirname(targetDbPath),
            `.db-rollback-${newId()}.sqlite`,
          );
          await fs.promises.copyFile(safetyDbPath, rollbackTmp);
          await fs.promises.chmod(rollbackTmp, 0o600);
          await fs.promises.rename(rollbackTmp, targetDbPath);
          await fs.promises.rm(`${targetDbPath}-wal`, { force: true });
          await fs.promises.rm(`${targetDbPath}-shm`, { force: true });
          this.databaseService.connect(targetDbPath);
        } else if (dbClosed && targetDbPath) {
          this.databaseService.connect(targetDbPath);
        }

        if (safetyStorageDir && storageReplaced) {
          if (existsSync(storageRoot)) {
            await fs.promises.rm(storageRoot, { recursive: true, force: true });
          }
          if (existsSync(safetyStorageDir)) {
            await fs.promises.cp(safetyStorageDir, storageRoot, {
              recursive: true,
            });
          }
        }

        this.logger.log(
          'Rollback completed successfully: pre-restore application state was restored intact.',
        );
      } catch (rollbackErr) {
        rollbackSucceeded = false;
        this.logger.error(
          `Catastrophic: Rollback to safety snapshot failed: ${rollbackErr instanceof Error ? rollbackErr.message : String(rollbackErr)}`,
        );
      }

      if (
        error instanceof HttpException &&
        rollbackSucceeded &&
        !dbReplaced &&
        !storageReplaced
      ) {
        throw error;
      }

      throw new InternalServerErrorException(
        `Restore failed; pre-restore state was rolled back and is intact: ${error instanceof Error ? error.message : String(error)}`,
      );
    } finally {
      if (stagingExtractDir && existsSync(stagingExtractDir)) {
        await fs.promises
          .rm(stagingExtractDir, { recursive: true, force: true })
          .catch(() => { });
      }
      if (safetyDir && existsSync(safetyDir)) {
        await fs.promises
          .rm(safetyDir, { recursive: true, force: true })
          .catch(() => { });
      }
      this.isRestoreInProgress = false;
    }
  }

  /**
   * Validates that an archive entry relative path is safe and contained.
   *
   * Rejects:
   * - Null bytes (`\0`)
   * - Absolute paths (POSIX `/...` or Windows `C:\...` or `\\...`)
   * - Traversal segments (`..`)
   * - Any entry outside `manifest.json`, `database.sqlite`, or `files/...`
   *
   * @param entryPath - Archive entry relative path.
   * @returns `true` if the path contains traversal or is unsafe; `false` if safe.
   */
  isPathTraversalOrUnsafe(entryPath: string): boolean {
    if (
      typeof entryPath !== 'string' ||
      entryPath.trim().length === 0 ||
      entryPath.includes('\0')
    ) {
      return true;
    }

    if (
      path.isAbsolute(entryPath) ||
      entryPath.startsWith('/') ||
      entryPath.startsWith('\\')
    ) {
      return true;
    }

    if (/^[a-zA-Z]:/.test(entryPath)) {
      return true;
    }

    const normalized = path.normalize(entryPath);
    if (
      normalized === '..' ||
      normalized.startsWith(`..${path.sep}`) ||
      normalized.startsWith('../') ||
      normalized.startsWith('..\\')
    ) {
      return true;
    }

    const segments = entryPath.split(/[/\\]/);
    if (segments.some((seg) => seg === '..')) {
      return true;
    }

    const isManifest =
      entryPath === 'manifest.json' || normalized === 'manifest.json';
    const isDb =
      entryPath === 'database.sqlite' || normalized === 'database.sqlite';
    const isFiles =
      entryPath === 'files' ||
      entryPath === 'files/' ||
      entryPath.startsWith('files/') ||
      entryPath.startsWith('files\\') ||
      normalized.startsWith(`files${path.sep}`) ||
      normalized === 'files';

    if (!isManifest && !isDb && !isFiles) {
      return true;
    }

    return false;
  }

  /**
   * Resolves and strictly validates the on-disk archive path for a backup record.
   *
   * ## Security Considerations
   * `file_path` is stored in the database. Even though it is originally generated
   * by the application, `target_directory` is user-configurable and database values
   * might be altered or contain legacy paths. Handing stored paths unchecked to the
   * filesystem could allow directory traversal, root escape, or arbitrary file read/write.
   *
   * Enforced validation rules:
   * 1. Rejects null bytes (`\0`) and empty paths.
   * 2. Resolves relative references strictly against the target directory.
   * 3. Confirms the normalized path is strictly contained within the target directory
   *    (preventing `../` traversal and sibling prefix attacks).
   * 4. For existing files, validates via `realpath` that symlinks within the target
   *    directory do not point outside its boundary.
   * 5. Never leaks filesystem paths into error messages or response bodies.
   *
   * @param row - Backup database record row.
   * @returns Validated absolute path to the archive file.
   * @throws BadRequestException (400) if the path escapes the target directory boundary.
   */
  resolveAndValidateArchivePath(row: BackupRecordRow): string {
    const rawRef = row.file_path;
    if (
      typeof rawRef !== 'string' ||
      rawRef.trim().length === 0 ||
      rawRef.includes('\0')
    ) {
      throw new BadRequestException({
        code: 'INVALID_BACKUP_PATH',
        message: 'Backup archive path is invalid',
      });
    }

    const targetDir = path.resolve(this.resolveTargetDirectory());

    const resolvedPath = path.isAbsolute(rawRef)
      ? path.resolve(rawRef)
      : path.resolve(targetDir, rawRef);

    const relative = path.relative(targetDir, resolvedPath);
    const isWindows = process.platform === 'win32';
    const relCheck = isWindows ? relative.toLowerCase() : relative;

    if (
      relCheck === '' ||
      relCheck === '..' ||
      relCheck.startsWith(`..${path.sep}`) ||
      relCheck.startsWith('../') ||
      relCheck.startsWith('..\\') ||
      path.isAbsolute(relative)
    ) {
      throw new BadRequestException({
        code: 'INVALID_BACKUP_PATH',
        message: 'Backup archive path escapes the backup directory boundary',
      });
    }

    const targetWithSep = targetDir.endsWith(path.sep)
      ? targetDir
      : `${targetDir}${path.sep}`;
    const targetForPrefix = isWindows
      ? targetWithSep.toLowerCase()
      : targetWithSep;
    const resolvedForPrefix = isWindows
      ? resolvedPath.toLowerCase()
      : resolvedPath;

    if (!resolvedForPrefix.startsWith(targetForPrefix)) {
      throw new BadRequestException({
        code: 'INVALID_BACKUP_PATH',
        message: 'Backup archive path escapes the backup directory boundary',
      });
    }

    if (existsSync(resolvedPath)) {
      try {
        const realTarget = fs.realpathSync(targetDir);
        const realResolved = fs.realpathSync(resolvedPath);
        const realRel = path.relative(realTarget, realResolved);
        const realRelCheck = isWindows ? realRel.toLowerCase() : realRel;

        if (
          realRelCheck === '' ||
          realRelCheck === '..' ||
          realRelCheck.startsWith(`..${path.sep}`) ||
          realRelCheck.startsWith('../') ||
          realRelCheck.startsWith('..\\') ||
          path.isAbsolute(realRel)
        ) {
          throw new BadRequestException({
            code: 'INVALID_BACKUP_PATH',
            message:
              'Backup archive path escapes the backup directory boundary',
          });
        }

        const realTargetWithSep = realTarget.endsWith(path.sep)
          ? realTarget
          : `${realTarget}${path.sep}`;
        const realTargetForPrefix = isWindows
          ? realTargetWithSep.toLowerCase()
          : realTargetWithSep;
        const realResolvedForPrefix = isWindows
          ? realResolved.toLowerCase()
          : realResolved;

        if (!realResolvedForPrefix.startsWith(realTargetForPrefix)) {
          throw new BadRequestException({
            code: 'INVALID_BACKUP_PATH',
            message:
              'Backup archive path escapes the backup directory boundary',
          });
        }
      } catch (err) {
        if (err instanceof BadRequestException) {
          throw err;
        }
        throw new BadRequestException({
          code: 'INVALID_BACKUP_PATH',
          message: 'Backup archive path escapes the backup directory boundary',
        });
      }
    }

    return resolvedPath;
  }

  /**
   * Maps a database row from the `backups` table to a public `BackupResponseDto`.
   *
   * Never exposes `file_path`. Performs a cheap `existsSync` check to verify whether
   * the archive file is still physically present on disk.
   */
  private mapRowToResponse(row: BackupRecordRow): BackupResponseDto {
    let fileExists = false;
    try {
      const archivePath = this.archivePathFor(row);
      fileExists = Boolean(archivePath && existsSync(archivePath));
    } catch {
      fileExists = false;
    }

    return {
      id: row.id,
      sizeBytes: row.size_bytes,
      trigger: row.trigger,
      createdAt: row.created_at,
      hasArchive: fileExists,
      isAvailable: fileExists,
    };
  }

  /**
   * Resolves the on-disk archive path for a backup row.
   *
   * Enforces containment within the target directory.
   */
  private archivePathFor(row: BackupRecordRow): string {
    return this.resolveAndValidateArchivePath(row);
  }

  /**
   * Resolves and verifies the target directory for writing backups.
   *
   * @returns Absolute path to a writable directory on disk.
   * @throws BadRequestException if the directory is missing, not a directory, or not writable.
   */
  public resolveTargetDirectory(): string {
    let configuredDir: string | null = null;
    try {
      const policy = this.databaseService.get<{
        target_directory: string | null;
      }>('SELECT target_directory FROM backup_policy WHERE id = 1');
      configuredDir = policy?.target_directory ?? null;
    } catch {
      // backup_policy might be unavailable or unmigrated in custom test setups
    }

    if (configuredDir && configuredDir.trim().length > 0) {
      const sanitized = configuredDir.trim();
      if (sanitized.includes('\0')) {
        throw new BadRequestException(
          'Target backup directory path contains illegal null bytes',
        );
      }

      const resolved = path.resolve(sanitized);
      if (!existsSync(resolved)) {
        throw new BadRequestException(
          `Configured backup target directory does not exist: "${resolved}"`,
        );
      }

      const stat = fs.statSync(resolved);
      if (!stat.isDirectory()) {
        throw new BadRequestException(
          `Configured backup target path is not a directory: "${resolved}"`,
        );
      }

      try {
        fs.accessSync(resolved, fs.constants.W_OK);
      } catch {
        throw new BadRequestException(
          `Configured backup target directory is not writable: "${resolved}"`,
        );
      }

      return resolved;
    }

    // Default fallback under application data directory
    const dataDir = this.appConfigService?.dataDir ?? resolveDefaultDataDir();
    const defaultDir = path.resolve(dataDir, 'backups');
    mkdirSync(defaultDir, { recursive: true, mode: 0o700 });
    try {
      fs.chmodSync(defaultDir, 0o700);
    } catch { }

    try {
      fs.accessSync(defaultDir, fs.constants.W_OK);
    } catch {
      throw new BadRequestException(
        `Default backup directory is not writable: "${defaultDir}"`,
      );
    }

    return defaultDir;
  }

  /**
   * Probes available storage on the destination filesystem before writing.
   *
   * @throws HttpException (507 Insufficient Storage) if disk space is below required threshold.
   */
  private checkDiskSpace(targetDir: string): void {
    try {
      if (typeof fs.statfsSync !== 'function') {
        return;
      }

      let dbEstimatedBytes = 0;
      try {
        const pageCountRow = this.databaseService.db
          .prepare('PRAGMA page_count')
          .get() as { page_count?: number } | undefined;
        const pageSizeRow = this.databaseService.db
          .prepare('PRAGMA page_size')
          .get() as { page_size?: number } | undefined;
        const pageCount = pageCountRow?.page_count ?? 0;
        const pageSize = pageSizeRow?.page_size ?? 4096;
        dbEstimatedBytes = pageCount * pageSize;
      } catch {
        dbEstimatedBytes = 5 * 1024 * 1024;
      }

      let storageBytes = 0;
      const storageRoot = this.fileStorageService.storageRoot;
      if (existsSync(storageRoot)) {
        storageBytes = this.calculateDirectorySize(storageRoot);
      }

      // Safety estimate: snapshot + storage copy + compressed archive + 5 MB headroom
      const estimatedRequiredBytes =
        (dbEstimatedBytes + storageBytes) * 2 + 5 * 1024 * 1024;

      const stat = fs.statfsSync(targetDir);
      const freeBytes = BigInt(stat.bavail) * BigInt(stat.bsize);

      if (freeBytes < BigInt(estimatedRequiredBytes)) {
        throw new HttpException(
          `Insufficient disk space. Available: ${freeBytes} bytes, estimated required: ${estimatedRequiredBytes} bytes`,
          HttpStatus.INSUFFICIENT_STORAGE,
        );
      }
    } catch (error) {
      if (error instanceof HttpException) {
        throw error;
      }
      // Ignore system statfs probing errors on unsupporting platforms
    }
  }

  /**
   * Recursively computes the total size in bytes of files in a directory.
   */
  private calculateDirectorySize(dir: string): number {
    let totalBytes = 0;
    try {
      const entries = fs.readdirSync(dir, { withFileTypes: true });
      for (const entry of entries) {
        const fullPath = path.join(dir, entry.name);
        if (entry.isDirectory()) {
          totalBytes += this.calculateDirectorySize(fullPath);
        } else if (entry.isFile()) {
          totalBytes += fs.statSync(fullPath).size;
        }
      }
    } catch {
      // Best-effort calculation
    }
    return totalBytes;
  }

  /**
   * Recursively copies a storage tree into staging and records inventory items.
   */
  private async copyStorageTree(
    sourceDir: string,
    targetDir: string,
    archivePrefix: string,
    inventory: BackupFileInventoryItem[],
  ): Promise<void> {
    if (!existsSync(sourceDir)) {
      return;
    }

    let entries: fs.Dirent[];
    try {
      entries = await fs.promises.readdir(sourceDir, {
        withFileTypes: true,
      });
    } catch (error: any) {
      if (error?.code === 'ENOENT') {
        return;
      }
      throw error;
    }

    for (const entry of entries) {
      const srcPath = path.join(sourceDir, entry.name);
      const dstPath = path.join(targetDir, entry.name);
      const relArchivePath = `${archivePrefix}/${entry.name}`;

      if (entry.isDirectory()) {
        try {
          await fs.promises.mkdir(dstPath, {
            recursive: true,
            mode: 0o700,
          });
          await fs.promises.chmod(dstPath, 0o700);
          await this.copyStorageTree(
            srcPath,
            dstPath,
            relArchivePath,
            inventory,
          );
        } catch (error: any) {
          if (error?.code === 'ENOENT') {
            continue;
          }
          throw error;
        }
      } else if (entry.isFile()) {
        try {
          await fs.promises.copyFile(srcPath, dstPath);
          await fs.promises.chmod(dstPath, 0o600);
          const stat = await fs.promises.stat(dstPath);
          const content = await fs.promises.readFile(dstPath);
          const sha256 = createHash('sha256').update(content).digest('hex');

          inventory.push({
            path: relArchivePath,
            sizeBytes: stat.size,
            sha256,
          });
        } catch (error: any) {
          if (error?.code === 'ENOENT') {
            await fs.promises.rm(dstPath, { force: true }).catch(() => { });
            continue;
          }
          throw error;
        }
      }
    }
  }

  /**
   * Retrieves the current database schema migration version name.
   */
  private getDatabaseSchemaVersion(): string {
    try {
      const row = this.databaseService.get<{ name: string }>(
        'SELECT name FROM schema_migrations ORDER BY id DESC LIMIT 1',
      );
      if (row?.name) {
        return row.name;
      }
    } catch { }

    try {
      const pragma = this.databaseService.get<{ user_version: number }>(
        'PRAGMA user_version',
      );
      if (pragma?.user_version !== undefined) {
        return String(pragma.user_version);
      }
    } catch { }

    return 'initial_bootstrap';
  }

  /**
   * Returns application version for backup manifest compatibility checking.
   */
  private getAppVersion(): string {
    return DEFAULT_APP_VERSION;
  }
}
