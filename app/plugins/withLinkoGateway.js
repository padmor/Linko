const { withSettingsGradle, withAppBuildGradle } = require("@expo/config-plugins");

const GATEWAY_INCLUDE = "include ':gateway'\nproject(':gateway').projectDir = new File(rootProject.projectDir, '../../android/gateway')";
const MOBILE_REPOSITORY = "maven { url = uri(new File(settingsDir, '../../android/mobile-repo')) }";
const MOBILE_DEPENDENCY = 'implementation "com.linko.mobile:mobile:0.1.0"';

function withGatewayProject(config) {
  config = withSettingsGradle(config, (mod) => {
    if (!mod.modResults.contents.includes("project(':gateway')")) {
      mod.modResults.contents += `\n// Linko native gateway library\n${GATEWAY_INCLUDE}\n`;
    }

    if (!mod.modResults.contents.includes(MOBILE_REPOSITORY)) {
      const repositoriesBlock =
        /(dependencyResolutionManagement\\s*\\{[\\s\\S]*?repositories\\s*\\{)/;

      if (!repositoriesBlock.test(mod.modResults.contents)) {
        throw new Error(
          "Linko requires dependencyResolutionManagement.repositories in the Android settings file."
        );
      }

      mod.modResults.contents = mod.modResults.contents.replace(
        repositoriesBlock,
        (match) => `${match}\n        ${MOBILE_REPOSITORY}`
      );
    }

    return mod;
  });

  config = withAppBuildGradle(config, (mod) => {
    const dependencies = [
      "implementation project(':gateway')",
      MOBILE_DEPENDENCY
    ];

    for (const dependency of dependencies) {
      if (!mod.modResults.contents.includes(dependency)) {
        mod.modResults.contents = mod.modResults.contents.replace(
          /dependencies\\s*\\{/,
          (match) => `${match}\n    ${dependency}`
        );
      }
    }

    return mod;
  });

  return config;
}

module.exports = withGatewayProject;
