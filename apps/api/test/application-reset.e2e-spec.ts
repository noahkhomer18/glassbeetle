import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { afterAll, beforeAll, beforeEach, describe, expect, it, vi } from 'vitest';
import { newId } from '../src/common/persistence/identifiers.js';
import { nowIso } from '../src/common/persistence/timestamps.js';
import { FileStorageService } from '../src/file-storage/file-storage.service.js';
import { createTestApp, type TestApp } from './harness/index.js';

describe('Application reset endpoint (e2e)', () => {
  let testApp: TestApp;
  let fileStorageService: FileStorageService;

  beforeAll(async () => {
    testApp = await createTestApp();
    fileStorageService = testApp.app.get(FileStorageService);
  });

  afterAll(async () => {
    await testApp.close();
  });

  beforeEach(() => {
    testApp.reset();
  });

  const count = (table: string): number => {
    const row = testApp.db.get<{ count: number }>(
      `SELECT COUNT(*) AS count FROM ${table}`,
    );
    return row?.count ?? 0;
  };

  describe('POST /api/v1/application/reset - Confirmation validation', () => {
    it('rejects reset without confirmation with 400 Bad Request and clears nothing', async () => {
      // Seed an agent
      testApp.fixtures.createAgent({ name: 'Safe Agent' });
      expect(count('agents')).toBe(1);

      const response = await testApp
        .request()
        .post('/api/v1/application/reset')
        .send({})
        .expect(400);

      expect(response.body).toMatchObject({
        statusCode: 400,
        code: 'CONFIRMATION_REQUIRED',
        message: expect.stringMatching(/confirmation/i),
      });

      // Assert nothing deleted
      expect(count('agents')).toBe(1);
    });

    it('rejects reset with invalid confirmation string ("false", "no") with 400 Bad Request', async () => {
      testApp.fixtures.createAgent({ name: 'Safe Agent 2' });

      await testApp
        .request()
        .post('/api/v1/application/reset')
        .send({ confirm: 'false' })
        .expect(400);

      await testApp
        .request()
        .post('/api/v1/application/reset')
        .send({ confirm: 'no' })
        .expect(400);

      await testApp
        .request()
        .post('/api/v1/application/reset?confirm=false')
        .expect(400);

      expect(count('agents')).toBe(1);
    });

    it('rejects unknown request body properties with 400 Bad Request', async () => {
      await testApp
        .request()
        .post('/api/v1/application/reset')
        .send({ confirm: 'true', unknownField: 123 })
        .expect(400);
    });
  });

  describe('POST /api/v1/application/reset - Already empty database', () => {
    it('succeeds on an already-empty installation without error', async () => {
      const response = await testApp
        .request()
        .post('/api/v1/application/reset')
        .send({ confirm: 'true' })
        .expect(200);

      expect(response.body).toMatchObject({
        status: 'completed',
        message: expect.stringMatching(/completed successfully/i),
        cleared: {
          agentsCleared: 0,
          chatsCleared: 0,
          messagesCleared: 0,
          backupsPreserved: true,
          providersPreserved: false,
        },
        resetAt: expect.any(String),
      });

      // Assert backup_policy exists with defaults
      const policy = testApp.db.get<{
        enabled: number;
        frequency: string;
        retention_count: number;
        target_directory: string | null;
      }>('SELECT * FROM backup_policy WHERE id = 1');
      expect(policy).toBeDefined();
      expect(policy?.enabled).toBe(0);
      expect(policy?.frequency).toBe('daily');
      expect(policy?.retention_count).toBe(7);
      expect(policy?.target_directory).toBeNull();
    });
  });

  describe('POST /api/v1/application/reset - Confirmation variants', () => {
    it('authorizes reset via ?confirm=true query parameter with empty body', async () => {
      testApp.fixtures.createAgent({ name: 'Query Agent' });

      const response = await testApp
        .request()
        .post('/api/v1/application/reset?confirm=true')
        .expect(200);

      expect(response.body.status).toBe('completed');
      expect(count('agents')).toBe(0);
    });

    it('authorizes reset via typed phrase { confirm: "RESET" }', async () => {
      testApp.fixtures.createAgent({ name: 'Typed Phrase Agent' });

      const response = await testApp
        .request()
        .post('/api/v1/application/reset')
        .send({ confirm: 'RESET' })
        .expect(200);

      expect(response.body.status).toBe('completed');
      expect(count('agents')).toBe(0);
    });
  });

  describe('POST /api/v1/application/reset - Fully populated installation reset', () => {
    it('clears all user data, removes files, resets singletons, and preserves backups and master.key', async () => {
      // 1. Fully populate the installation
      const prompt = testApp.fixtures.createSystemPrompt({ name: 'Dev Prompt' });
      const provider = testApp.fixtures.createProvider({ name: 'Dev Provider' });
      const model = testApp.fixtures.createModel({ provider_id: provider.id });
      testApp.fixtures.createCredential(provider.id);

      // Upload stored files
      const pic = await fileStorageService.write(
        'pictures',
        Buffer.from([0xff, 0xd8, 0xff, 0xe0, 0x00, 0x10, 0x4a, 0x46, 0x49, 0x46, 0x00]),
        { extension: 'jpg' },
      );
      const projImg = await fileStorageService.write(
        'project-images',
        Buffer.from([0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a]),
        { extension: 'png' },
      );
      const artBlob = await fileStorageService.write(
        'artifacts',
        Buffer.from('e2e artifact content'),
      );

      const agent = testApp.fixtures.createAgent({
        name: 'Dev Agent',
        system_prompt_id: prompt.id,
        model_id: model.id,
        picture_path: pic.reference,
      });
      testApp.fixtures.createAgentMemory({ agent_id: agent.id });
      const team = testApp.fixtures.createTeam({ name: 'Dev Team' });
      testApp.fixtures.createTeamMember(team.id, agent.id);
      const project = testApp.fixtures.createProject({
        name: 'Dev Project',
        image_path: projImg.reference,
      });
      const chat = testApp.fixtures.createChat({
        agent_id: agent.id,
        project_id: project.id,
      });
      testApp.fixtures.createMessage({ chat_id: chat.id });
      testApp.fixtures.createSharedMemory({ content: 'Shared Memory Content' });
      const artifact = testApp.fixtures.createArtifact({
        project_id: project.id,
        chat_id: chat.id,
        agent_id: agent.id,
        file_path: artBlob.reference,
      });
      testApp.fixtures.createArtifactVersion({
        artifact_id: artifact.id,
        version: 2,
        file_path: artBlob.reference,
      });
      testApp.fixtures.createUsageEvent({
        agent_id: agent.id,
        provider_id: provider.id,
        model_id: model.id,
        chat_id: chat.id,
      });

      // Modify singletons to non-defaults
      testApp.db.run(
        "UPDATE backup_policy SET enabled = 1, frequency = 'weekly', retention_count = 14 WHERE id = 1",
      );
      testApp.db.run(
        "UPDATE user_profile SET display_name = 'Custom Profile', about = 'Engineer' WHERE singleton = 1",
      );
      testApp.db.run(
        "UPDATE spend_budget SET limit_usd = 250.0, period = 'weekly' WHERE singleton = 1",
      );

      // Create a physical backup archive in <dataDir>/backups
      const backupsDir = path.join(testApp.dataDir, 'backups');
      fs.mkdirSync(backupsDir, { recursive: true });
      const backupId = newId();
      const backupArchiveName = `backup-${backupId}.tar.gz`;
      const backupArchivePath = path.join(backupsDir, backupArchiveName);
      fs.writeFileSync(backupArchivePath, 'tar gz simulated content');
      testApp.db.run(
        'INSERT INTO backups (id, file_path, size_bytes, trigger, created_at) VALUES (?, ?, ?, ?, ?)',
        [backupId, backupArchiveName, 26, 'manual', nowIso()],
      );

      // Create a master.key in <dataDir>
      const masterKeyPath = path.join(testApp.dataDir, 'master.key');
      fs.writeFileSync(masterKeyPath, Buffer.alloc(32, 0x99));

      // Assert existence before reset
      expect(await fileStorageService.exists(pic.reference)).toBe(true);
      expect(await fileStorageService.exists(projImg.reference)).toBe(true);
      expect(await fileStorageService.exists(artBlob.reference)).toBe(true);
      expect(fs.existsSync(backupArchivePath)).toBe(true);
      expect(fs.existsSync(masterKeyPath)).toBe(true);

      // 2. Execute reset request
      const response = await testApp
        .request()
        .post('/api/v1/application/reset')
        .send({ confirm: 'true' })
        .expect(200);

      // 3. Validate response payload
      expect(response.body).toMatchObject({
        status: 'completed',
        message: expect.any(String),
        cleared: {
          agentsCleared: 1,
          chatsCleared: 1,
          messagesCleared: 1,
          memoriesCleared: 2,
          projectsCleared: 1,
          artifactsCleared: 2,
          systemPromptsCleared: 1,
          usageEventsCleared: 1,
          providersCleared: 1,
          modelsCleared: 1,
          filesDeleted: 3,
          backupsPreserved: true,
          providersPreserved: false,
          preResetBackupCreated: false,
          preResetBackupId: null,
        },
        nextSteps: expect.arrayContaining([
          expect.stringMatching(/providers and credentials/i),
          expect.stringMatching(/backup archives have been preserved/i),
        ]),
        resetAt: expect.any(String),
      });

      // 4. Assert table-by-table what was cleared
      expect(count('agents')).toBe(0);
      expect(count('agent_memories')).toBe(0);
      expect(count('teams')).toBe(0);
      expect(count('team_members')).toBe(0);
      expect(count('projects')).toBe(0);
      expect(count('chats')).toBe(0);
      expect(count('messages')).toBe(0);
      expect(count('shared_memories')).toBe(0);
      expect(count('artifacts')).toBe(0);
      expect(count('artifact_versions')).toBe(0);
      expect(count('system_prompts')).toBe(0);
      expect(count('usage_events')).toBe(0);
      expect(count('providers')).toBe(0);
      expect(count('models')).toBe(0);
      expect(count('provider_credentials')).toBe(0);

      // 5. Assert backups survived
      expect(count('backups')).toBe(1);
      expect(fs.existsSync(backupArchivePath)).toBe(true);

      // 6. Assert files in storage were deleted and no orphans remain
      expect(await fileStorageService.exists(pic.reference)).toBe(false);
      expect(await fileStorageService.exists(projImg.reference)).toBe(false);
      expect(await fileStorageService.exists(artBlob.reference)).toBe(false);

      const storageRoot = fileStorageService.storageRoot;
      for (const bucket of ['pictures', 'project-images', 'artifacts']) {
        const bucketPath = path.join(storageRoot, bucket);
        if (fs.existsSync(bucketPath)) {
          const files = fs.readdirSync(bucketPath);
          expect(files).toHaveLength(0);
        }
      }

      // 7. Assert master.key survived
      expect(fs.existsSync(masterKeyPath)).toBe(true);

      // 8. Assert singletons reset to defaults
      const policy = testApp.db.get<{
        id: number;
        enabled: number;
        frequency: string;
        retention_count: number;
        target_directory: string | null;
      }>('SELECT * FROM backup_policy WHERE id = 1');
      expect(policy?.enabled).toBe(0);
      expect(policy?.frequency).toBe('daily');
      expect(policy?.retention_count).toBe(7);
      expect(policy?.target_directory).toBeNull();

      const profile = testApp.db.get<{
        display_name: string;
        about: string | null;
        picture_path: string | null;
      }>('SELECT * FROM user_profile WHERE singleton = 1');
      expect(profile?.display_name).toBe('Test User');
      expect(profile?.about).toBeNull();
      expect(profile?.picture_path).toBeNull();

      const budget = testApp.db.get<{
        limit_usd: number | null;
        period: string;
      }>('SELECT * FROM spend_budget WHERE singleton = 1');
      expect(budget?.limit_usd).toBeNull();
      expect(budget?.period).toBe('monthly');
    });

    it('preserves providers when keepProviders: true option is supplied', async () => {
      const provider = testApp.fixtures.createProvider({ name: 'Keep Provider' });
      testApp.fixtures.createModel({ provider_id: provider.id });
      testApp.fixtures.createCredential(provider.id);
      testApp.fixtures.createAgent({ name: 'Drop Agent' });

      const response = await testApp
        .request()
        .post('/api/v1/application/reset')
        .send({ confirm: 'true', keepProviders: true })
        .expect(200);

      expect(response.body.cleared.providersPreserved).toBe(true);
      expect(response.body.cleared.providersCleared).toBe(0);
      expect(response.body.cleared.agentsCleared).toBe(1);

      expect(count('providers')).toBe(1);
      expect(count('models')).toBe(1);
      expect(count('provider_credentials')).toBe(1);
      expect(count('agents')).toBe(0);
    });
  });

  describe('POST /api/v1/application/reset - keepBackups: false', () => {
    it('deletes a backup archive from the default backup directory and reports it', async () => {
      const created = await testApp
        .request()
        .post('/api/v1/application/backups')
        .send({})
        .expect(201);

      const backupRow = testApp.db.get<{ file_path: string }>(
        'SELECT file_path FROM backups WHERE id = ?',
        [created.body.id],
      );
      expect(backupRow?.file_path).toBeDefined();

      const archivePath = path.join(
        testApp.dataDir,
        'backups',
        backupRow!.file_path,
      );
      expect(fs.existsSync(archivePath)).toBe(true);

      const response = await testApp
        .request()
        .post('/api/v1/application/reset')
        .send({ confirm: 'RESET', keepBackups: false })
        .expect(200);

      expect(fs.existsSync(archivePath)).toBe(false);
      expect(count('backups')).toBe(0);
      expect(response.body.cleared.backupsPreserved).toBe(false);
      expect(response.body.cleared.filesDeleted).toBeGreaterThanOrEqual(1);
      expect(response.body.nextSteps).toEqual(
        expect.arrayContaining([
          expect.stringMatching(/backup archives have been removed from disk/i),
        ]),
      );
    });

    it('deletes a backup archive from a custom target directory captured before the policy reset', async () => {
      const customDir = fs.mkdtempSync(
        path.join(os.tmpdir(), 'glassbeetle-reset-custom-backups-'),
      );

      try {
        await testApp
          .request()
          .put('/api/v1/application/backup-policy')
          .send({
            enabled: false,
            frequency: 'daily',
            retentionCount: 7,
            targetDirectory: customDir,
          })
          .expect(200);

        const created = await testApp
          .request()
          .post('/api/v1/application/backups')
          .send({})
          .expect(201);

        const backupRow = testApp.db.get<{ file_path: string }>(
          'SELECT file_path FROM backups WHERE id = ?',
          [created.body.id],
        );
        expect(backupRow?.file_path).toBeDefined();

        const archivePath = path.join(customDir, backupRow!.file_path);
        expect(fs.existsSync(archivePath)).toBe(true);

        const response = await testApp
          .request()
          .post('/api/v1/application/reset')
          .send({ confirm: 'RESET', keepBackups: false })
          .expect(200);

        expect(fs.existsSync(archivePath)).toBe(false);
        expect(count('backups')).toBe(0);
        expect(response.body.cleared.backupsPreserved).toBe(false);
        expect(response.body.cleared.filesDeleted).toBeGreaterThanOrEqual(1);
        expect(response.body.nextSteps).toEqual(
          expect.arrayContaining([
            expect.stringMatching(
              /backup archives have been removed from disk/i,
            ),
          ]),
        );

        const policy = testApp.db.get<{ target_directory: string | null }>(
          'SELECT target_directory FROM backup_policy WHERE id = 1',
        );
        expect(policy?.target_directory).toBeNull();
      } finally {
        fs.rmSync(customDir, { recursive: true, force: true });
      }
    });

    it('removes stray archives and .tmp files without touching unrelated files in a custom directory', async () => {
      const customDir = fs.mkdtempSync(
        path.join(os.tmpdir(), 'glassbeetle-reset-stray-backups-'),
      );

      try {
        await testApp
          .request()
          .put('/api/v1/application/backup-policy')
          .send({
            enabled: false,
            frequency: 'daily',
            retentionCount: 7,
            targetDirectory: customDir,
          })
          .expect(200);

        const strayArchive = path.join(customDir, `backup-${newId()}.tar.gz`);
        const strayTmp = path.join(customDir, `backup-${newId()}.tar.gz.tmp`);
        const unrelatedFile = path.join(customDir, 'notes.txt');
        fs.writeFileSync(strayArchive, 'stray archive');
        fs.writeFileSync(strayTmp, 'partial archive');
        fs.writeFileSync(unrelatedFile, 'keep me');

        const response = await testApp
          .request()
          .post('/api/v1/application/reset')
          .send({ confirm: 'RESET', keepBackups: false })
          .expect(200);

        expect(fs.existsSync(strayArchive)).toBe(false);
        expect(fs.existsSync(strayTmp)).toBe(false);
        expect(fs.existsSync(unrelatedFile)).toBe(true);
        expect(response.body.cleared.filesDeleted).toBeGreaterThanOrEqual(2);
        expect(response.body.nextSteps).toEqual(
          expect.arrayContaining([
            expect.stringMatching(
              /backup archives have been removed from disk/i,
            ),
          ]),
        );
      } finally {
        fs.rmSync(customDir, { recursive: true, force: true });
      }
    });

    it('keeps the pre-reset safety backup it was asked to create', async () => {
      const older = await testApp
        .request()
        .post('/api/v1/application/backups')
        .send({})
        .expect(201);
      const olderRow = testApp.db.get<{ file_path: string }>(
        'SELECT file_path FROM backups WHERE id = ?',
        [older.body.id],
      );
      const olderPath = path.join(testApp.dataDir, 'backups', olderRow!.file_path);
      expect(fs.existsSync(olderPath)).toBe(true);

      const response = await testApp
        .request()
        .post('/api/v1/application/reset')
        .send({ confirm: 'RESET', keepBackups: false, createBackup: true })
        .expect(200);

      const safetyId = response.body.cleared.preResetBackupId;
      expect(safetyId).toEqual(expect.any(String));
      const rows = testApp.db.all<{ id: string; file_path: string }>(
        'SELECT id, file_path FROM backups',
      );
      expect(rows.map((row) => row.id)).toEqual([safetyId]);
      expect(fs.existsSync(path.join(testApp.dataDir, 'backups', rows[0].file_path))).toBe(true);
      expect(fs.existsSync(olderPath)).toBe(false);
      expect(response.body.nextSteps).toEqual(
        expect.arrayContaining([
          expect.stringMatching(/except the pre-reset safety backup/i),
        ]),
      );
    });
  });

  describe('Post-reset application functionality', () => {
    it('allows creating an agent, chat, and message after reset', async () => {
      // Reset first
      await testApp
        .request()
        .post('/api/v1/application/reset')
        .send({ confirm: 'true' })
        .expect(200);

      // 1. Create a fresh agent
      const agentRes = await testApp
        .request()
        .post('/api/v1/agents')
        .send({
          name: 'Post-Reset Agent',
          instructions: 'Help the user after reset',
        })
        .expect(201);

      const agentId = agentRes.body.id;
      expect(agentId).toBeDefined();

      // 2. Create a fresh chat for this agent
      const chatRes = await testApp
        .request()
        .post('/api/v1/chats')
        .send({
          title: 'Post-Reset Conversation',
          agentId,
        })
        .expect(201);

      const chatId = chatRes.body.id;
      expect(chatId).toBeDefined();

      // 3. Create a fresh message in this chat
      const messageRes = await testApp
        .request()
        .post(`/api/v1/chats/${chatId}/messages`)
        .send({
          role: 'user',
          content: 'Hello freshly reset world!',
        })
        .expect(201);

      expect(messageRes.body.id).toBeDefined();
      expect(messageRes.body.content).toBe('Hello freshly reset world!');

      // Assert rows are in the database
      expect(count('agents')).toBe(1);
      expect(count('chats')).toBe(1);
      expect(count('messages')).toBe(1);
    });
  });

  describe('Rollback on mid-reset error', () => {
    it('rolls back database modifications when a failure occurs during reset', async () => {
      testApp.fixtures.createAgent({ name: 'Survivor Agent' });
      expect(count('agents')).toBe(1);

      // Spy on databaseService.run to fail mid-clearing
      const dbSpy = vi.spyOn(testApp.db, 'run').mockImplementation((sql: string) => {
        if (sql.includes('DELETE FROM agents')) {
          throw new Error('Simulated SQLite fatal write error');
        }
        return (testApp.db as any).db.prepare(sql).run();
      });

      const response = await testApp
        .request()
        .post('/api/v1/application/reset')
        .send({ confirm: 'true' })
        .expect(500);

      expect(response.body).toMatchObject({
        statusCode: 500,
        code: 'RESET_FAILED',
        message: expect.stringMatching(/rolled back/i),
      });

      dbSpy.mockRestore();

      // Assert agent was NOT deleted due to transactional rollback
      expect(count('agents')).toBe(1);
    });
  });
});
