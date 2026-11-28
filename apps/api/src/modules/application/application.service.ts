import {
  BadRequestException,
  ConflictException,
  Injectable,
  InternalServerErrorException,
  Logger,
  Optional,
} from '@nestjs/common';
import fs from 'node:fs';
import path from 'node:path';
import { newId } from '../../common/persistence/identifiers.js';
import { nowIso } from '../../common/persistence/timestamps.js';
import { AppConfigService } from '../../config/app-config.service.js';
import { resolveDefaultDataDir } from '../../config/data-dir.js';
import { DatabaseService } from '../../database/database.service.js';
import { FileStorageService } from '../../file-storage/file-storage.service.js';
import { resolveUserProfileSeed } from '../user/user-profile.seed.js';
import { BackupsService } from './backups/backups.service.js';
import type {
  ResetApplicationDto,
  ResetApplicationResponseDto,
  ResetSummaryDto,
} from './dto/index.js';

/**
 * Options controlling the application reset operation.
 */
export interface ApplicationResetOptions extends ResetApplicationDto {
  /** Explicit confirmation parameter. Must be "true" or "RESET" */
  confirm?: string;
}

/** Backup archives written by BackupsService, and the temporary file it renames into place. */
const BACKUP_ARCHIVE_NAME = /^backup-.+\.tar\.gz(?:\.tmp)?$/;

interface BackupArchiveCleanup {
  /** Where archives are written, read before the backup policy is reset. */
  directory: string | null;
  /** Archive names from the `backups` rows being deleted. */
  fileNames: string[];
  /** The pre-reset safety backup, which is kept. */
  keepFileNames: Set<string>;
}

/**
 * Service managing the application reset lifecycle.
 *
 * ## Reset Semantics & Guarantees
 * 1. **Confirmation Requirement**: Requires explicit confirmation (`confirm === 'true'` or
 *    `confirm === 'RESET'`). Rejects unconfirmed invocations with `400 Bad Request`.
 * 2. **Concurrency Safety**: Rejects reset if a backup, restore, or reset is currently
 *    in progress with `409 Conflict`.
 * 3. **Optional Pre-Reset Safety Backup**: When requested (`createBackup: true`), captures
 *    a full database and file storage archive before modifying any active data.
 * 4. **Transactional Database Clearing**: Executes all table clearing and singleton re-seeding
 *    inside a single SQLite transaction in strict foreign-key dependency order. If any error
 *    occurs, the transaction rolls back cleanly, leaving the database state completely intact.
 * 5. **Consistent File Storage Cleanup**: Gathers stored file references before deletion and
 *    unlinks them after transaction commit. Sweeps user storage buckets (`pictures`,
 *    `project-images`, `artifacts`) to eliminate orphans. Preserves `backups/` by default.
 * 6. **Preservation of Backups & Encryption Key**: Physical backup archives and `master.key`
 *    are preserved to ensure existing backups remain restorable.
 * 7. **Prominent Logging**: Logs warnings before destruction begins and upon completion.
 */
@Injectable()
export class ApplicationService {
  private readonly logger = new Logger(ApplicationService.name);
  private isResetInProgress = false;

  constructor(
    private readonly databaseService: DatabaseService,
    private readonly fileStorageService: FileStorageService,
    @Optional() private readonly backupsService?: BackupsService,
    @Optional() private readonly appConfigService?: AppConfigService,
  ) {}

  /**
   * Reports whether an application reset operation is currently running.
   */
  public get isOperationInProgress(): boolean {
    return this.isResetInProgress;
  }

  /**
   * Resets the application to a clean, freshly-installed state.
   *
   * @param options - Reset configuration including explicit confirmation and preservation flags.
   * @returns Detailed summary of cleared entities, preserved components, and next steps.
   * @throws BadRequestException (400) if confirmation is missing or invalid.
   * @throws ConflictException (409) if a backup, restore, or reset is currently running.
   * @throws InternalServerErrorException (500) if reset fails; database changes are rolled back.
   */
  async reset(
    options: ApplicationResetOptions = {},
  ): Promise<ResetApplicationResponseDto> {
    const confirmation = options.confirm?.trim();
    if (confirmation !== 'true' && confirmation !== 'RESET') {
      throw new BadRequestException({
        code: 'CONFIRMATION_REQUIRED',
        message:
          'Explicit confirmation is required to reset the application (confirm must be "true" or "RESET")',
      });
    }

    if (this.isResetInProgress) {
      throw new ConflictException(
        'An application reset operation is already in progress',
      );
    }

    if (this.backupsService?.isOperationInProgress) {
      throw new ConflictException(
        'A backup or restore operation is already in progress',
      );
    }

    this.isResetInProgress = true;
    this.logger.warn(
      `Starting application reset with options: keepProviders=${Boolean(options.keepProviders)}, keepBackups=${options.keepBackups !== false}, createBackup=${Boolean(options.createBackup)}`,
    );

    const keepProviders = Boolean(options.keepProviders);
    const keepBackups = options.keepBackups !== false;
    const shouldCreateBackup = Boolean(options.createBackup);

    let preResetBackupId: string | null = null;

    try {
      // 1. Optional pre-reset safety snapshot
      if (shouldCreateBackup && this.backupsService) {
        this.logger.log('Creating automatic safety backup before application reset...');
        const backupResult = await this.backupsService.createBackup({
          trigger: 'manual',
          note: 'Automatic safety backup created before application reset',
        });
        preResetBackupId = backupResult.id;
        this.logger.log(`Safety pre-reset backup created: id="${preResetBackupId}"`);
      }

      // 2. Count existing rows for summary reporting
      const counts = this.gatherEntityCounts(keepProviders);

      // 3. Gather stored file references before clearing rows. The backup
      // directory is read here too: clearing resets the policy's target_directory.
      const fileReferences = this.gatherStoredFileReferences();
      const backupCleanup = keepBackups
        ? null
        : this.prepareBackupArchiveCleanup(preResetBackupId);

      // 4. Transactionally clear tables and re-seed singletons
      this.executeDatabaseClearing(keepProviders, keepBackups, preResetBackupId);

      // 5. Clean up files from storage after database transaction commit
      let filesDeleted = await this.cleanupStoredFiles(
        fileReferences,
        keepBackups,
      );
      let backupArchivesFailed = 0;
      if (backupCleanup) {
        const archives = await this.deleteBackupArchives(backupCleanup);
        filesDeleted += archives.deleted;
        backupArchivesFailed = archives.failed;
      }

      this.logger.warn(
        `Application reset completed successfully: cleared ${counts.agents} agents, ${counts.chats} chats, ${counts.messages} messages, ${counts.memories} memories, ${counts.projects} projects, ${counts.artifacts} artifacts, ${filesDeleted} files.`,
      );

      const summary: ResetSummaryDto = {
        agentsCleared: counts.agents,
        chatsCleared: counts.chats,
        messagesCleared: counts.messages,
        memoriesCleared: counts.memories,
        projectsCleared: counts.projects,
        artifactsCleared: counts.artifacts,
        systemPromptsCleared: counts.systemPrompts,
        usageEventsCleared: counts.usageEvents,
        providersCleared: counts.providers,
        modelsCleared: counts.models,
        filesDeleted,
        backupsPreserved: keepBackups,
        providersPreserved: keepProviders,
        preResetBackupCreated: Boolean(preResetBackupId),
        preResetBackupId,
      };

      const nextSteps = this.buildNextSteps(
        keepProviders,
        keepBackups,
        preResetBackupId,
        backupArchivesFailed,
      );

      return {
        status: 'completed',
        message:
          'Application reset completed successfully. The application has been returned to a clean, freshly-installed state.',
        cleared: summary,
        nextSteps,
        resetAt: nowIso(),
      };
    } catch (error) {
      if (
        error instanceof BadRequestException ||
        error instanceof ConflictException
      ) {
        throw error;
      }

      const errorMessage =
        error instanceof Error ? error.message : String(error);
      this.logger.error(
        `Application reset failed mid-flight: ${errorMessage}. Active state was preserved or rolled back.`,
        error instanceof Error ? error.stack : undefined,
      );

      throw new InternalServerErrorException({
        code: 'RESET_FAILED',
        message: `Application reset failed: ${errorMessage}. Database changes were rolled back and active state was preserved.`,
      });
    } finally {
      this.isResetInProgress = false;
    }
  }

  /**
   * Reads current row counts for entities to populate the reset summary.
   */
  private gatherEntityCounts(keepProviders: boolean) {
    const queryCount = (table: string): number => {
      try {
        const row = this.databaseService.get<{ count: number }>(
          `SELECT COUNT(*) AS count FROM ${table}`,
        );
        return row?.count ?? 0;
      } catch {
        return 0;
      }
    };

    return {
      agents: queryCount('agents'),
      chats: queryCount('chats'),
      messages: queryCount('messages'),
      memories: queryCount('agent_memories') + queryCount('shared_memories'),
      projects: queryCount('projects'),
      artifacts: queryCount('artifacts') + queryCount('artifact_versions'),
      systemPrompts: queryCount('system_prompts'),
      usageEvents: queryCount('usage_events'),
      providers: keepProviders ? 0 : queryCount('providers'),
      models: keepProviders ? 0 : queryCount('models'),
    };
  }

  /**
   * Collects all stored file references stored across application tables before deletion.
   */
  private gatherStoredFileReferences(): string[] {
    const references = new Set<string>();

    const collectFromQuery = (sql: string) => {
      try {
        const rows = this.databaseService.all<{ ref: string | null }>(sql);
        for (const row of rows) {
          if (row.ref && typeof row.ref === 'string' && row.ref.trim().length > 0) {
            references.add(row.ref.trim());
          }
        }
      } catch {
        // Table or column might not exist in specialized test fixtures
      }
    };

    collectFromQuery('SELECT picture_path AS ref FROM agents WHERE picture_path IS NOT NULL');
    collectFromQuery('SELECT picture_path AS ref FROM user_profile WHERE picture_path IS NOT NULL');
    collectFromQuery('SELECT image_path AS ref FROM projects WHERE image_path IS NOT NULL');
    collectFromQuery('SELECT file_path AS ref FROM artifacts WHERE file_path IS NOT NULL');
    collectFromQuery('SELECT file_path AS ref FROM artifact_versions WHERE file_path IS NOT NULL');

    return Array.from(references);
  }

  /**
   * Reads where backup archives are written and which ones the `backups` rows
   * name. `backups.file_path` is a bare file name in that directory, not a
   * storage reference, so FileStorageService cannot resolve it.
   */
  private prepareBackupArchiveCleanup(
    preResetBackupId: string | null,
  ): BackupArchiveCleanup {
    const fileNames: string[] = [];
    const keepFileNames = new Set<string>();
    try {
      const rows = this.databaseService.all<{ id: string; file_path: string | null }>(
        'SELECT id, file_path FROM backups WHERE file_path IS NOT NULL',
      );
      for (const row of rows) {
        const name = row.file_path?.trim();
        if (!name) continue;
        if (row.id === preResetBackupId) {
          keepFileNames.add(name);
        } else {
          fileNames.push(name);
        }
      }
    } catch {
      // Table might not exist in specialized test fixtures
    }

    let directory: string | null = null;
    try {
      directory = this.backupsService
        ? this.backupsService.resolveTargetDirectory()
        : path.resolve(this.appConfigService?.dataDir ?? resolveDefaultDataDir(), 'backups');
    } catch {
      // The message would name the configured directory, which must not be logged
      this.logger.warn('Could not resolve the backup directory during reset; backup archives may remain on disk.');
    }

    return { directory, fileNames, keepFileNames };
  }

  /**
   * Deletes the archives named by the cleared `backups` rows, then any other
   * `backup-*.tar.gz` or leftover `.tar.gz.tmp` in the same directory. Nothing
   * else in the directory is touched.
   */
  private async deleteBackupArchives(
    cleanup: BackupArchiveCleanup,
  ): Promise<{ deleted: number; failed: number }> {
    let deleted = 0;
    let failed = 0;
    const directory = cleanup.directory;
    if (!directory) {
      return { deleted, failed: cleanup.fileNames.length };
    }

    const attempted = new Set<string>(cleanup.keepFileNames);
    const remove = async (name: string) => {
      attempted.add(name);
      try {
        await fs.promises.unlink(path.join(directory, name));
        deleted++;
      } catch (err) {
        if ((err as NodeJS.ErrnoException).code !== 'ENOENT') {
          failed++;
        }
      }
    };

    for (const name of cleanup.fileNames) {
      if (attempted.has(name)) continue;
      // A name that is not a plain file name could point outside the directory
      if (path.basename(name) !== name || name === '.' || name === '..') {
        failed++;
        continue;
      }
      await remove(name);
    }

    let entries: fs.Dirent[] = [];
    try {
      entries = await fs.promises.readdir(directory, { withFileTypes: true });
    } catch (err) {
      if ((err as NodeJS.ErrnoException).code !== 'ENOENT') {
        failed++;
      }
    }
    for (const entry of entries) {
      if (entry.isFile() && BACKUP_ARCHIVE_NAME.test(entry.name) && !attempted.has(entry.name)) {
        await remove(entry.name);
      }
    }

    if (failed > 0) {
      this.logger.warn(`Could not delete ${failed} backup archive file(s) during reset.`);
    }
    return { deleted, failed };
  }

  /**
   * Executes the database deletions and singleton re-seeding within a single transaction.
   */
  private executeDatabaseClearing(
    keepProviders: boolean,
    keepBackups: boolean,
    preResetBackupId: string | null,
  ): void {
    this.databaseService.transaction(() => {
      // 1. Delete in reverse dependency order respecting foreign keys
      this.databaseService.run('DELETE FROM usage_events');
      this.databaseService.run('DELETE FROM artifact_versions');
      this.databaseService.run('DELETE FROM artifacts');
      this.databaseService.run('DELETE FROM messages');
      this.databaseService.run('DELETE FROM chats');
      this.databaseService.run('DELETE FROM team_members');
      this.databaseService.run('DELETE FROM teams');
      this.databaseService.run('DELETE FROM agent_memories');
      this.databaseService.run('DELETE FROM agents');
      this.databaseService.run('DELETE FROM projects');
      this.databaseService.run('DELETE FROM shared_memories');
      this.databaseService.run('DELETE FROM system_prompts');

      if (!keepProviders) {
        this.databaseService.run('DELETE FROM provider_credentials');
        this.databaseService.run('DELETE FROM models');
        this.databaseService.run('DELETE FROM providers');
      }

      if (!keepBackups) {
        // The safety backup this reset just created stays, so it can be restored
        this.databaseService.run('DELETE FROM backups WHERE id IS NOT ?', [
          preResetBackupId,
        ]);
      }

      const now = nowIso();

      // Reset backup_policy singleton (id = 1)
      const policyResult = this.databaseService.run(
        `UPDATE backup_policy
         SET enabled = 0,
             frequency = 'daily',
             retention_count = 7,
             target_directory = NULL,
             updated_at = ?
         WHERE id = 1`,
        [now],
      );
      if (policyResult.changes === 0) {
        this.databaseService.run(
          `INSERT INTO backup_policy (id, enabled, frequency, retention_count, target_directory, updated_at)
           VALUES (1, 0, 'daily', 7, NULL, ?)`,
          [now],
        );
      }

      // Reset user_profile singleton (singleton = 1)
      const seed = resolveUserProfileSeed(this.appConfigService?.defaultUserName);
      const profileResult = this.databaseService.run(
        `UPDATE user_profile
         SET display_name = ?,
             pronouns = NULL,
             about = NULL,
             locale = ?,
             timezone = ?,
             include_in_prompts = 1,
             picture_path = NULL,
             picture_updated_at = NULL,
             updated_at = ?
         WHERE singleton = 1`,
        [seed.displayName, seed.locale, seed.timezone, now],
      );
      if (profileResult.changes === 0) {
        this.databaseService.run(
          `INSERT INTO user_profile (id, singleton, display_name, locale, timezone, include_in_prompts, created_at, updated_at)
           VALUES (?, 1, ?, ?, ?, 1, ?, ?)`,
          [newId(), seed.displayName, seed.locale, seed.timezone, now, now],
        );
      }

      // Reset spend_budget singleton (singleton = 1)
      const budgetResult = this.databaseService.run(
        `UPDATE spend_budget
         SET limit_usd = NULL,
             period = 'monthly',
             updated_at = ?
         WHERE singleton = 1`,
        [now],
      );
      if (budgetResult.changes === 0) {
        this.databaseService.run(
          `INSERT INTO spend_budget (id, singleton, limit_usd, period, created_at, updated_at)
           VALUES (?, 1, NULL, 'monthly', ?, ?)`,
          [newId(), now, now],
        );
      }
    });
  }

  /**
   * Cleans up stored files from disk, catching and logging individual deletion errors as warnings.
   */
  private async cleanupStoredFiles(
    references: string[],
    keepBackups: boolean,
  ): Promise<number> {
    let deletedCount = 0;
    const deletedPaths = new Set<string>();

    // 1. Delete known database-referenced files via FileStorageService
    for (const ref of references) {
      try {
        const resolved = await this.fileStorageService.resolveAndVerify(ref);
        if (fs.existsSync(resolved) && fs.statSync(resolved).isFile()) {
          await this.fileStorageService.delete(ref);
          deletedCount++;
          deletedPaths.add(resolved);
        }
      } catch (err) {
        this.logger.warn(
          `Could not delete stored file during reset: "${ref}": ${err instanceof Error ? err.message : String(err)}`,
        );
      }
    }

    // 2. Clean up any unreferenced orphan files in user storage buckets
    const storageRoot = this.fileStorageService.storageRoot;
    const bucketsToSweep = ['pictures', 'project-images', 'artifacts'];
    if (!keepBackups) {
      bucketsToSweep.push('backups');
    }

    for (const bucket of bucketsToSweep) {
      const bucketDir = path.join(storageRoot, bucket);
      if (!fs.existsSync(bucketDir)) {
        continue;
      }

      try {
        const entries = await fs.promises.readdir(bucketDir, {
          withFileTypes: true,
        });
        for (const entry of entries) {
          if (entry.isFile()) {
            const filePath = path.join(bucketDir, entry.name);
            if (!deletedPaths.has(filePath)) {
              try {
                await fs.promises.unlink(filePath);
                deletedCount++;
                deletedPaths.add(filePath);
              } catch (unlinkErr) {
                this.logger.warn(
                  `Could not unlink orphan file in bucket "${bucket}": "${entry.name}": ${unlinkErr instanceof Error ? unlinkErr.message : String(unlinkErr)}`,
                );
              }
            }
          }
        }
      } catch (readErr) {
        this.logger.warn(
          `Could not read bucket directory "${bucketDir}" for reset cleanup: ${readErr instanceof Error ? readErr.message : String(readErr)}`,
        );
      }
    }

    return deletedCount;
  }

  /**
   * Generates informative guidance steps for the user based on reset options.
   */
  private buildNextSteps(
    keepProviders: boolean,
    keepBackups: boolean,
    preResetBackupId: string | null,
    backupArchivesFailed: number,
  ): string[] {
    const steps: string[] = [];

    if (preResetBackupId) {
      steps.push(
        `A safety pre-reset backup was created with ID "${preResetBackupId}". You can restore it if needed via POST /api/v1/application/backups/${preResetBackupId}/restore.`,
      );
    }

    if (keepProviders) {
      steps.push(
        'Configured providers, models, and credentials were preserved. You can immediately create agents and start chats.',
      );
    } else {
      steps.push(
        'Configure your LLM providers and credentials to resume using agents, chats, and completions.',
      );
    }

    if (keepBackups) {
      steps.push(
        'Existing backup archives have been preserved and can be restored at any time via POST /api/v1/application/backups/:backupId/restore.',
      );
    } else if (backupArchivesFailed > 0) {
      steps.push(
        `${backupArchivesFailed} backup archive file(s) could not be removed from disk.`,
      );
    } else if (preResetBackupId) {
      steps.push(
        'All backup metadata and physical backup archives except the pre-reset safety backup have been removed from disk.',
      );
    } else {
      steps.push(
        'All backup metadata and physical backup archives have been removed from disk.',
      );
    }

    steps.push(
      'The encryption master key (master.key) was preserved, ensuring archive compatibility.',
    );
    steps.push(
      'The backup policy has been restored to default values (disabled, daily frequency, 7 retention count).',
    );
    steps.push(
      'The user profile has been restored to default system seed values.',
    );

    return steps;
  }
}
