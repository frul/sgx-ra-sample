#include "settings.hpp"
#include "../common/settings_reader.hpp"

ServerSettings ReadServerSettings() {
    ServerSettings result;

    SettingsReader reader("settings.xml");

    result.ip = reader.ReadSetting("ip", "0.0.0.0");
    result.port = reader.ReadSetting("port", "0.0.0.0");
    result.public_key = reader.ReadSetting("public_key");
    result.spid = reader.ReadSetting("spid");
    result.primary_subscription_key = reader.ReadSetting("primary_subscription_key");
    result.secondary_subscription_key = reader.ReadSetting("secondary_subscription_key");
    result.ias_key_file = reader.ReadSetting("ias_key_file");

    return result;
}