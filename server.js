
const express = require('express');
const path = require('path');
const Pusher = require('pusher');

const app = express();
app.use(express.json());
app.use(express.urlencoded({ extended: false }));

const PORT = process.env.PORT || 3000;

// Initialize Pusher
// These should be set in Vercel Environment Variables
const pusher = new Pusher({
  appId: "2145695",
  key: "9619457411b436b0306b",
  secret: "56bdb6e4ce919fb4a12e",
  cluster: "ap2",
  useTLS: true
});

// Serve static files from public
app.use(express.static(path.join(__dirname, 'public')));

// Pusher Auth Endpoint for Presence Channels
app.post('/pusher/auth', (req, res) => {
  const socketId = req.body.socket_id;
  const channel = req.body.channel_name;
  const username = req.body.username;
  const publicKey = req.body.publicKey;

  const presenceData = {
    user_id: socketId,
    user_info: {
      username: username,
      publicKey: publicKey
    }
  };

  const auth = pusher.authenticate(socketId, channel, presenceData);
  res.send(auth);
});

// Endpoint to trigger messages
app.post('/api/messages', (req, res) => {
  const { to, from, encryptedMsg, type } = req.body;
  
  // Trigger event on the recipient's private channel
  pusher.trigger(`private-user-${to}`, 'client-receive-message', {
    from,
    encryptedMsg
  });
  
  res.status(200).send('Sent');
});

// Endpoint to share keys
app.post('/api/share-key', (req, res) => {
  const { to, from, encryptedAESKey } = req.body;
  
  pusher.trigger(`private-user-${to}`, 'client-receive-aes-key', {
    from,
    encryptedAESKey
  });
  
  res.status(200).send('Key Shared');
});

app.listen(PORT, () => {
  console.log(`Server running on http://localhost:${PORT}`);
});
