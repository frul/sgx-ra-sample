#include "settings.hpp"
#include "../../common/settings_reader.hpp"

Settings ReadSettings() {
    Settings result;

    SettingsReader reader("settings.xml");

    result.ip = reader.ReadSetting("ip", "0.0.0.0");
    result.port = reader.ReadSetting("port", "0.0.0.0");
    result.public_key = reader.ReadSetting("public_key");

    return result;
}