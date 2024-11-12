import cors from 'cors';
import express from 'express';
import http from 'http';
import {Server} from 'socket.io';
import {config} from './config';
import {initializeSocket} from './controllers/device-controller';

const app = express();
const server = http.createServer(app);

const io = new Server(server, {
    cors: config.socket.cors,
    pingTimeout: config.socket.pingTimeout,
    pingInterval: config.socket.pingInterval
});

app.use(cors());

server.listen(config.server.port, () => {
    console.log(`Server listening on port ${config.server.port}`);
});

initializeSocket(io);

// Graceful shutdown handling
const cleanup = () => {
    console.log('Shutting down...');
    server.close(() => {
        console.log('Server stopped');
        process.exit(0);
    });
};

process.on('SIGINT', cleanup);
process.on('SIGTERM', cleanup);
process.once('SIGUSR2', () => {
    cleanup();
    process.kill(process.pid, 'SIGUSR2');
});

process.on('uncaughtException', (error) => {
    console.error('Uncaught Exception:', error);
    cleanup();
});

process.on('unhandledRejection', (reason, promise) => {
    console.error('Unhandled Rejection at:', promise, 'reason:', reason);
    cleanup();
});