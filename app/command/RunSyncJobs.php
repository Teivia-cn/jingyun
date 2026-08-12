<?php

declare(strict_types=1);

namespace app\command;

use app\service\ProviderSyncService;
use app\service\SyncSchedulerService;
use Throwable;
use think\console\Command;
use think\console\Input;
use think\console\Output;
use think\console\input\Option;

final class RunSyncJobs extends Command
{
    protected function configure(): void
    {
        $this->setName('sync:run')
            ->setDescription('Run queued cloud provider synchronization jobs.')
            ->addOption('job', null, Option::VALUE_REQUIRED, 'Run one sync job by ID.')
            ->addOption('due', null, Option::VALUE_NONE, 'Queue due scheduled jobs before execution.')
            ->addOption('limit', null, Option::VALUE_REQUIRED, 'Maximum queued jobs to execute per pass.', 10)
            ->addOption('loop', null, Option::VALUE_NONE, 'Keep polling for queued jobs.')
            ->addOption('sleep', null, Option::VALUE_REQUIRED, 'Seconds to wait between polling passes.', 5);
    }

    protected function execute(Input $input, Output $output): int
    {
        $service = new ProviderSyncService();
        $jobId = $input->getOption('job');

        try {
            if ($jobId !== null && $jobId !== '') {
                $job = $service->run((int) $jobId);
                $output->writeln(sprintf('Job %d finished with status: %s', (int) $job['id'], (string) $job['status']));
                return $job['status'] === 'succeeded' ? 0 : 1;
            }

            $limit = max(1, min(100, (int) $input->getOption('limit')));
            $sleepSeconds = max(1, min(300, (int) $input->getOption('sleep')));
            $loop = (bool) $input->getOption('loop');
            do {
                if ($input->getOption('due')) {
                    $queued = (new SyncSchedulerService())->dispatchDue($limit);
                    $output->writeln('Queued ' . $queued . ' due sync job(s).');
                }
                $processed = 0;
                while ($processed < $limit && ($job = $service->runNext()) !== null) {
                    $processed++;
                    $output->writeln(sprintf('Job %d finished with status: %s', (int) $job['id'], (string) $job['status']));
                }
                $output->writeln('Processed ' . $processed . ' sync job(s).');
                if ($loop) {
                    sleep($sleepSeconds);
                }
            } while ($loop);

            return 0;
        } catch (Throwable $exception) {
            $output->error($exception->getMessage());
            return 1;
        }
    }
}
