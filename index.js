const express = require("express");
const bodyParser = require("body-parser");
const cors = require("cors");
const { Sequelize, DataTypes } = require("sequelize");
const jwt = require("jsonwebtoken");
const bcrypt = require("bcryptjs");

// Initialize Express app
const app = express();
const port = process.env.PORT || 5000;

// Middleware
app.use(bodyParser.json());
app.use(cors());

// Initialize Sequelize
const sequelize = new Sequelize(
  "postgres://postgres:admin@localhost:5432/file_management"
);

// Define models
const User = sequelize.define('User', {
    username: {
      type: DataTypes.STRING,
      allowNull: false,
      unique: true,
    },
    password: {
      type: DataTypes.STRING,
      allowNull: false,
    },
  });
  
  const Folder = sequelize.define('Folder', {
    name: {
      type: DataTypes.STRING,
      allowNull: false,
    },
    date_modified: {
      type: DataTypes.DATE,
      allowNull: false,
    },
  });
  
  const File = sequelize.define('File', {
    name: {
      type: DataTypes.STRING,
      allowNull: false,
    },
    size: {
      type: DataTypes.INTEGER,
      allowNull: false,
    },
    date_modified: {
      type: DataTypes.DATE,
      allowNull: false,
    },
    parent_id: {
      type: DataTypes.INTEGER,
      allowNull: true,
      references: {
        model: Folder,
        key: 'id',
      }
    },
  });
  
  // Sync database
  sequelize.sync().then(() => {
    console.log('Database & tables created!');
  });
  
  // Routes
  app.post('/register', async (req, res) => {
    const { username, password } = req.body;
    if (!username || !password) {
      return res.status(400).send({ error: 'Username and password are required!' });
    }
    const hashedPassword = bcrypt.hashSync(password, 8);
    try {
      const user = await User.create({ username, password: hashedPassword });
      res.status(201).send({ message: 'User registered successfully!' });
    } catch (error) {
      res.status(400).send({ error: error.message });
    }
  });
  
  app.post('/login', async (req, res) => {
    const { username, password } = req.body;
    if (!username || !password) {
      return res.status(400).send({ error: 'Username and password are required!' });
    }
    const user = await User.findOne({ where: { username } });
    if (!user) {
      return res.status(404).send({ error: 'User not found!' });
    }
  
    const isPasswordValid = bcrypt.compareSync(password, user.password);
    if (!isPasswordValid) {
      return res.status(401).send({ error: 'Invalid password!' });
    }
  
    const token = jwt.sign({ id: user.id }, 'secret', { expiresIn: 86400 });
    res.status(200).send({ token });
  });
  
  // Protect routes with JWT middleware
  const verifyToken = (req, res, next) => {
    const token = req.headers['x-access-token'];
    if (!token) {
      return res.status(403).send({ error: 'No token provided!' });
    }
  
    jwt.verify(token, 'secret', (err, decoded) => {
      if (err) {
        return res.status(500).send({ error: 'Failed to authenticate token.' });
      }
  
      req.userId = decoded.id;
      next();
    });
  };
  
  // File Routes
  app.get('/files', verifyToken, async (req, res) => {
    try {
      const files = await File.findAll();
      res.status(200).send(files);
    } catch (error) {
      res.status(500).send({ error: error.message });
    }
  });
  
  app.get('/files/:id', verifyToken, async (req, res) => {
    const fileId = req.params.id;
    try {
      const file = await File.findByPk(fileId);
      if (!file) {
        return res.status(404).send({ error: 'File not found!' });
      }
      res.status(200).send(file);
    } catch (error) {
      res.status(500).send({ error: error.message });
    }
  });
  
  app.post('/files', verifyToken, async (req, res) => {
    const { name, size, date_modified, parent_id } = req.body;
    if (!name || !size || !date_modified) {
      return res.status(400).send({ error: 'Name, size, and date modified are required!' });
    }
    try {
      const file = await File.create({ name, size, date_modified, parent_id });
      res.status(201).send(file);
    } catch (error) {
      res.status(400).send({ error: error.message });
    }
  });
  
  app.put('/files/:id', verifyToken, async (req, res) => {
    const fileId = req.params.id;
    const { name } = req.body;
  
    if (!name) {
      return res.status(400).send({ error: 'New file name is required!' });
    }
  
    try {
      const file = await File.findByPk(fileId);
      if (!file) {
        return res.status(404).send({ error: 'File not found!' });
      }
  
      file.name = name;
      await file.save();
      res.status(200).send(file);
    } catch (error) {
      res.status(500).send({ error: error.message });
    }
  });
  
  app.delete('/files/:id', verifyToken, async (req, res) => {
    const fileId = req.params.id;
  
    try {
      const file = await File.findByPk(fileId);
      if (!file) {
        return res.status(404).send({ error: 'File not found!' });
      }
  
      await file.destroy();
      res.status(200).send({ message: 'File deleted successfully!' });
    } catch (error) {
      res.status(500).send({ error: error.message });
    }
  });
  
  // Folder Routes
  app.post('/folders', verifyToken, async (req, res) => {
    const { name, date_modified } = req.body;
    if (!name || !date_modified) {
      return res.status(400).send({ error: 'Name and date modified are required!' });
    }
    try {
      const folder = await Folder.create({ name, date_modified });
      res.status(201).send(folder);
    } catch (error) {
      res.status(400).send({ error: error.message });
    }
  });
  
  app.get('/folders/:id/files', verifyToken, async (req, res) => {
    const folderId = req.params.id;
    try {
      const files = await File.findAll({ where: { parent_id: folderId } });
      res.status(200).send(files);
    } catch (error) {
      res.status(500).send({ error: error.message });
    }
  });
  
  app.get('/folders', verifyToken, async (req, res) => {
    try {
      const folders = await Folder.findAll();
      res.status(200).send(folders);
    } catch (error) {
      res.status(500).send({ error: error.message });
    }
  });
  
  app.get('/folders/:id', verifyToken, async (req, res) => {
    const folderId = req.params.id;
    try {
      const folder = await Folder.findByPk(folderId);
      if (!folder) {
        return res.status(404).send({ error: 'Folder not found!' });
      }
      res.status(200).send(folder);
    } catch (error) {
      res.status(500).send({ error: error.message });
    }
  });
  
  app.put('/folders/:id', verifyToken, async (req, res) => {
    const folderId = req.params.id;
    const { name } = req.body;
  
    if (!name) {
      return res.status(400).send({ error: 'New folder name is required!' });
    }
  
    try {
      const folder = await Folder.findByPk(folderId);
      if (!folder) {
        return res.status(404).send({ error: 'Folder not found!' });
      }
  
      folder.name = name;
      await folder.save();
      res.status(200).send(folder);
    } catch (error) {
      res.status(500).send({ error: error.message });
    }
  });
  
  app.delete('/folders/:id', verifyToken, async (req, res) => {
    const folderId = req.params.id;
  
    try {
      const folder = await Folder.findByPk(folderId);
      if (!folder) {
        return res.status(404).send({ error: 'Folder not found!' });
      }
  
      await folder.destroy();
      res.status(200).send({ message: 'Folder deleted successfully!' });
    } catch (error) {
      res.status(500).send({ error: error.message });
    }
  });
  
  // Start the server
  app.listen(port, () => {
    console.log(`Server is running on port ${port}`);
  });