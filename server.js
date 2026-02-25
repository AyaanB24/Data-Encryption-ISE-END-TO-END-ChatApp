
const express = require('express');
const http = require('http');
const { Server } = require('socket.io');
const path = require('path');

const app = express();
const server = http.createServer(app);
const io = new Server(server);

const PORT = process.env.PORT || 3000;

// Serve static files from public and utils
app.use(express.static(path.join(__dirname, 'public')));
app.use('/utils', express.static(path.join(__dirname, 'utils')));

// Store users and their public keys
const users = new Map();

io.on('connection', (socket) => {
    console.log('User connected:', socket.id);

    // User joins with a username and their RSA Public Key
    socket.on('join', ({ username, publicKey }) => {
        users.set(socket.id, { username, publicKey });
        console.log(`${username} joined with public key.`);

        // Broadcast updated user list
        io.emit('user-list', Array.from(users.entries()).map(([id, data]) => ({
            id,
            username: data.username,
            publicKey: data.publicKey
        })));
    });

    // Forward encrypted AES key from sender to receiver
    socket.on('share-aes-key', ({ to, encryptedAESKey }) => {
        io.to(to).emit('receive-aes-key', {
            from: socket.id,
            encryptedAESKey
        });
    });

    // Forward encrypted message
    socket.on('chat-message', ({ to, encryptedMsg }) => {
        io.to(to).emit('receive-message', {
            from: socket.id,
            encryptedMsg
        });
    });

    socket.on('disconnect', () => {
        users.delete(socket.id);
        io.emit('user-list', Array.from(users.entries()).map(([id, data]) => ({
            id,
            username: data.username,
            publicKey: data.publicKey
        })));
        console.log('User disconnected:', socket.id);
    });
});

server.listen(PORT, () => {
    console.log(`Server running on http://localhost:${PORT}`);
});
