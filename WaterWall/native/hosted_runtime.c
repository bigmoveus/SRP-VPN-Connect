#include "hosted_runtime.h"

#include "SRPNEPacketDevice.h"
#include "core_settings.h"
#include "imported_tunnels.h"
#include "loggers/core_logger.h"
#include "node_builder/config_policy.h"
#include "os_helpers.h"
#include "wwapi.h"

static void srpWaterWallHostedFinalize(void) { destroyCoreSettings(); }

static SRPWaterWallHostedStopRequested srpWaterWallStopRequested;

static bool srpWaterWallHostedCheckpoint(void) {
  if (srpWaterWallStopRequested != NULL && srpWaterWallStopRequested()) {
    discard requestProgramShutdown(0);
  }
  signalmanagerConsumePendingShutdownSignal();
  return !applicationShutdownWasRequested();
}

static int srpWaterWallHostedFailure(int code) {
  const application_shutdown_request_result_e result =
      signalmanagerArbitrateStartupFailure(code == 0 ? 1 : code);
  if (result == kApplicationShutdownRequestUnavailable &&
      !applicationShutdownWasRequested()) {
    srpNEPacketDeviceClose();
    return code == 0 ? 1 : code;
  }
  const int exit_code = applicationShutdownCoordinateHosted();
  srpNEPacketDeviceClose();
  return exit_code;
}

int srpWaterWallHostedRun(const char *core_json, const char *nodes_json,
                          SRPWaterWallHostedReady ready,
                          SRPWaterWallHostedStopRequested stop_requested,
                          logger_handler log_handler) {
  if (core_json == NULL || nodes_json == NULL) {
    return EINVAL;
  }

  srpWaterWallStopRequested = stop_requested;
  configPolicyRestrict();
  initWLibc();
  ww_startup_result_t startup_result = wwStartupSuccess();
  ww_startup_context_t core_settings_scope = {0};
  wwStartupContextBegin(&core_settings_scope);
  const bool core_parsed = parseCoreSettings(core_json, strlen(core_json));
  startup_result = wwStartupContextEnd(&core_settings_scope);
  if (!core_parsed) {
    destroyCoreSettings();
    srpNEPacketDeviceClose();
    return startup_result.exit_code == 0 ? 1 : startup_result.exit_code;
  }

  getCoreSettings()->workers_count = 1;
  getCoreSettings()->ram_profile = kRamProfileS1Memory;
  getCoreSettings()->splice_enabled = false;

  ww_construction_data_t runtime_data = {
      .workers_count = 1,
      .ram_profile = kRamProfileS1Memory,
      .mtu_size = getCoreSettings()->mtu_size,
      .splice_disabled = true,
      .tcp_tune_enabled = false,
      .dns_options = getCoreSettings()->dns_options,
      .domain_strategy = getCoreSettings()->domain_strategy,
      .internal_logger_data =
          (logger_construction_data_t){
              .log_file_path = getCoreSettings()->internal_log_file_fullpath,
              .log_level = getCoreSettings()->internal_log_level,
              .log_console = getCoreSettings()->internal_log_console},
      .core_logger_data =
          (logger_construction_data_t){
              .log_file_path = getCoreSettings()->core_log_file_fullpath,
              .log_level = getCoreSettings()->core_log_level,
              .log_console = getCoreSettings()->core_log_console},
      .network_logger_data =
          (logger_construction_data_t){
              .log_file_path = getCoreSettings()->network_log_file_fullpath,
              .log_level = getCoreSettings()->network_log_level,
              .log_console = getCoreSettings()->network_log_console},
      .dns_logger_data =
          (logger_construction_data_t){
              .log_file_path = getCoreSettings()->dns_log_file_fullpath,
              .log_level = getCoreSettings()->dns_log_level,
              .log_console = getCoreSettings()->dns_log_console},
      .application_finalizer = srpWaterWallHostedFinalize,
  };

  startup_result = createGlobalState(runtime_data);
  if (!wwStartupSucceeded(startup_result)) {
    if (GSTATE.application_shutdown == NULL) {
      destroyCoreSettings();
      srpNEPacketDeviceClose();
      return startup_result.exit_code;
    }
    return srpWaterWallHostedFailure(startup_result.exit_code);
  }

  if (log_handler != NULL) {
    loggerSetHandler(GSTATE.internal_logger, log_handler);
    loggerSetHandler(GSTATE.core_logger, log_handler);
    loggerSetHandler(GSTATE.network_logger, log_handler);
    loggerSetHandler(GSTATE.dns_logger, log_handler);
  }

  startup_result = loadImportedTunnelsIntoCore();
  if (!wwStartupSucceeded(startup_result) || !srpWaterWallHostedCheckpoint()) {
    return srpWaterWallHostedFailure(startup_result.exit_code);
  }

  ww_startup_context_t config_scope = {0};
  wwStartupContextBegin(&config_scope);
  config_file_t *config = configfileParseBuffer(nodes_json, strlen(nodes_json),
                                                "hosted-nodes.json");
  startup_result = wwStartupContextEnd(&config_scope);
  if (config == NULL) {
    return srpWaterWallHostedFailure(startup_result.exit_code);
  }
  startup_result = nodemanagerBuildConfigFile(config);
  if (!wwStartupSucceeded(startup_result) || !srpWaterWallHostedCheckpoint()) {
    return srpWaterWallHostedFailure(startup_result.exit_code);
  }

  startup_result = nodemanagerStartConfigs();
  if (!wwStartupSucceeded(startup_result) || !srpWaterWallHostedCheckpoint()) {
    return srpWaterWallHostedFailure(startup_result.exit_code);
  }
  startup_result = socketmanagerStart();
  if (!wwStartupSucceeded(startup_result) || !srpWaterWallHostedCheckpoint()) {
    return srpWaterWallHostedFailure(startup_result.exit_code);
  }

  const int result = globalstateRunHostedMainThread(ready);
  srpNEPacketDeviceClose();
  return result;
}
