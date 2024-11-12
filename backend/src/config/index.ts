export const config = {
    server: {
        port: process.env.PORT || 3002,
        host: process.env.HOST || 'localhost'
    },
    socket: {
        pingTimeout: parseInt(process.env.SOCKET_PING_TIMEOUT || '20000'),
        pingInterval: parseInt(process.env.SOCKET_PING_INTERVAL || '25000'),
        cors: {
            origin: "*",
            methods: ["GET", "POST"]
        }
    },
    monitoring: {
        deviceMetricsInterval: parseInt(process.env.DEVICE_METRICS_INTERVAL || '5000'),
        healthCheckInterval: parseInt(process.env.HEALTH_CHECK_INTERVAL || '30000')
    }
};