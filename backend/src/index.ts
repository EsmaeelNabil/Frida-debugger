import cors from 'cors';
import express from 'express';
import http from 'http';
import { Server } from 'socket.io';
import { initializeSocket } from './controllers/device-controller';

const app = express();
const server = http.createServer(app);

const io = new Server(server, {
  cors: {
    origin: "http://localhost:3000",
    methods: ["GET", "POST"],
  },
});

app.use(cors());

server.listen(3002, () => {
  console.log("Listening on port 3002");
});

// Initialize socket connection and handle events
initializeSocket(io);

// Gracefully shut down the server on exit signals
process.once("SIGUSR2", () => {
  process.kill(process.pid, "SIGUSR2");
});

process.on("SIGINT", () => {
  console.log("Shutting down...");
  server.close(() => {
    console.log("Server stopped");
    process.exit(0);
  });
});
