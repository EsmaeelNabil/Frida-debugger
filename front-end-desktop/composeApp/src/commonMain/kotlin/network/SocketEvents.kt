package network

/**
 * This enum class represents the socket events that are used for communication between the client and the server.
 * Each event corresponds to a specific action or request in the application.
 *
 * Example usage:
 * ```kotlin
 * val socket = SocketManager.getClient()
 * socket.emit(SocketEvents.GET_DEVICES.name)
 * ```
 * @property GET_DEVICES This event is used to request the list of devices from the server.
 * @property DEVICES This event is used by the server to send the list of devices to the client.
 * @property GET_APPS This event is used to request the list of applications from the server.
 * @property APPS This event is used by the server to send the list of applications to the client.
 * @property ATTACH This event is used to attach to an application.
 * @property LAUNCH This event is used to launch an application.
 * @property UNLOAD_SCRIPTS This event is used to unload scripts from an application.
 * @property ON_MESSAGE This event is used to send a message from the server to the client.
*/
enum class SocketEvents() {
    GET_DEVICES,
    DEVICES,
    GET_APPS,
    APPS,
    ATTACH,
    LAUNCH,
    UNLOAD_SCRIPTS,
    ON_MESSAGE,
}