const { withSettingsGradle, withAppBuildGradle } = require("@expo/config-plugins");

const GATEWAY_INCLUDE = "include ':gateway'\nproject(':gateway').projectDir = new File(rootProject.projectDir, '../../android/gateway')";

function withGatewayProject(config) {
  config = withSettingsGradle(config, (mod) => {
    if (!mod.modResults.contents.includes("project(':gateway')")) {
      mod.modResults.contents += `\n// Linko native gateway library\n${GATEWAY_INCLUDE}\n`;
    }
    return mod;
  });

  config = withAppBuildGradle(config, (mod) => {
    const dependency = "implementation project(':gateway')";
    if (!mod.modResults.contents.includes(dependency)) {
      mod.modResults.contents = mod.modResults.contents.replace(
        /dependencies\s*\{/,
        (match) => `${match}\n    ${dependency}`
      );
    }
    return mod;
  });

  return config;
}

module.exports = withGatewayProject;
