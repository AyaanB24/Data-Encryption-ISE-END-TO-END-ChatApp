
const express = require('express');
const path = require('path');
const Pusher = require('pusher');

const app = express();
app.use(express.json());
app.use(express.urlencoded({ extended: false }));

const PORT = process.env.PORT || 3000;

const pusher = new Pusher({
  appId: "2145695",
  key: "9619457411b436b0306b",
  secret: "56bdb6e4ce919fb4a12e",
  cluster: "ap2",
  useTLS: true
});

app.use(express.static(path.join(__dirname, 'public')));

app.post('/pusher/auth', (req, res) => {
  const socketId = req.body.socket_id;
  const channel = req.body.channel_name;
  
  // Presence channel data
  let presenceData = null;
  if (channel.startsWith('presence-')) {
    presenceData = {
      user_id: socketId,
      user_info: {
        username: req.body.username,
        publicKey: req.body.publicKey
      }
    };
  }

  const auth = pusher.authenticate(socketId, channel, presenceData);
  res.send(auth);
});

app.post('/api/messages', (req, res) => {
  const { to, from, encryptedMsg } = req.body;
  console.log(`Relaying message from ${from} to ${to}`);
  
  pusher.trigger(`private-user-${to}`, 'receive-message', {
    from,
    encryptedMsg
  }).then(() => res.status(200).send('Sent'))
    .catch(err => {
      console.error('Pusher Trigger Error:', err);
      res.status(500).send(err);
    });
});

app.post('/api/share-key', (req, res) => {
  const { to, from, encryptedAESKey } = req.body;
  console.log(`Relaying AES Key from ${from} to ${to}`);
  
  pusher.trigger(`private-user-${to}`, 'receive-aes-key', {
    from,
    encryptedAESKey
  }).then(() => res.status(200).send('Key Shared'))
    .catch(err => {
      console.error('Pusher Key Share Error:', err);
      res.status(500).send(err);
    });
});

app.listen(PORT, () => {
  console.log(`Server running on port ${PORT}`);
});
