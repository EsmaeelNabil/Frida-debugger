package network

enum class SocketEvents() {
    GET_DEVICES,
    DEVICES,
    GET_APPS,
    APPS,
    ATTACH,
    UNLOAD_SCRIPTS,
    ON_MESSAGE,
    RUN_APP;
}