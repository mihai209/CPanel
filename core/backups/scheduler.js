function startBackupPolicyScheduler({
    ServerBackupPolicy,
    jobQueue,
    intervalMs = 60 * 1000,
    bootInfo,
    bootWarn
}) {
    if (typeof bootWarn === 'function') {
        bootWarn('backup policy scheduler is disabled; use sftp backup workflow');
    }
    return function stop() {};
}

module.exports = {
    startBackupPolicyScheduler
};
