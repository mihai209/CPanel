const { createLegacyStartupHelpers } = require('./legacy/startup-migration-helpers');
const { createLegacyRuntimeHelpers } = require('./legacy/runtime-helpers');

function createLegacyHelpers(deps) {
    const startupHelpers = createLegacyStartupHelpers(deps);
    const runtimeHelpers = createLegacyRuntimeHelpers({
        ...deps,
        ...startupHelpers
    });

    return {
        ...startupHelpers,
        ...runtimeHelpers
    };
}

module.exports = { createLegacyHelpers };
