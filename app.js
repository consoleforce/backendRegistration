const express = require('express');
const bodyParser = require('body-parser');
const session = require('express-session');
const { Pool } = require('pg');
const bcrypt = require('bcrypt');
const app = express();  
const port = 3000;

const pool = new Pool({
  user: 'postgres',
  host: 'localhost',
  database: 'registration1',
  password: 'qwerty123',
  port: 5432,
});

app.use(bodyParser.urlencoded({ extended: true }));
app.use(express.static('public'));
app.use(bodyParser.urlencoded({ extended: true }));
app.use(session({ secret: '123', resave: false, saveUninitialized: false }));

app.set('view engine', 'ejs');



function isAuthenticated(req, res, next) {
  if (req.session.user) {
    return next();
  }
  res.redirect('/login');
}


app.get('/', (req, res) => {
  res.sendFile(__dirname + '/home.html');
});


app.get('/registration', (req, res) => {
  res.sendFile(__dirname + '/registration.html');
});

app.get('/logout', (req, res) => {
  res.sendFile(__dirname + '/login.html');
});

app.post('/registration', async (req, res) => {
  const { username, email, password, role } = req.body;


  const existingUser = await pool.query('SELECT * FROM user1 WHERE username = $1', [username]);

  if (existingUser.rows.length > 0) {

    return res.send('Username already exists. Please choose a different username.');
  }

  const hashedPassword = await bcrypt.hash(password, 10);

  const result = await pool.query('INSERT INTO user1 (username, email, password, role) VALUES ($1, $2, $3, $4)', [username, email, hashedPassword, role]);
  
  res.redirect('/login');
});



app.get('/login', (req, res) => {
  res.sendFile(__dirname + '/login.html');
});

app.post('/login', async (req, res) => {
  const { username, password } = req.body;

  const result = await pool.query('SELECT * FROM user1 WHERE username = $1', [username]);

  if (result.rows.length > 0) {
    const user = result.rows[0];
    const isPasswordValid = await bcrypt.compare(password, user.password);

    if (isPasswordValid) {
      req.session.user = user;
      res.redirect(`/${user.role}`);
    } else {

      res.send('Incorrect password. Please try again.');
    }
  } else {

    res.send('Username not found. Please check your username or register.');
  }
});

function authorizeRole(allowedRoles) {
  return (req, res, next) => {
    const userRole = req.session.user ? req.session.user.role : null;

    if (allowedRoles.includes(userRole)) {
      return next();
    }

    res.status(403).send('Access Forbidden: You do not have permission to access this resource.');
  };
}





// Admin Route
app.get('/admin', isAuthenticated, authorizeRole(['admin']), async (req, res) => {
  try {
    const result = await pool.query('SELECT * FROM user1');
    const users = result.rows;
    res.render('admin', { user: req.session.user, users });
  } catch (error) {
    console.error('Error retrieving user list:', error);
    res.status(500).send('Internal Server Error');
  }
});

app.post('/admin/update-role', isAuthenticated, authorizeRole(['admin']), async (req, res) => {
  const { userId, role } = req.body;

  try {
    await pool.query('UPDATE user1 SET role = $1 WHERE id = $2', [role, userId]);
    res.redirect('/admin');
  } catch (error) {
    console.error('Error updating user role:', error);
    res.status(500).send('Internal Server Error');
  }
});

app.post('/admin/delete-user', isAuthenticated, authorizeRole(['admin']), async (req, res) => {
  const { userId } = req.body;

  try {
    await pool.query('DELETE FROM user1 WHERE id = $1', [userId]);
    res.redirect('/admin');
  } catch (error) {
    console.error('Error deleting user:', error);
    res.status(500).send('Internal Server Error');
  }
});



// Moderator Route  
app.get('/moderator', isAuthenticated, authorizeRole(['admin', 'moderator']), async (req, res) => {
  try {
    const result = await pool.query('SELECT * FROM user1');
    const users = result.rows;

    res.render('moderator', { user: req.session.user, users });
  } catch (error) {
    console.error('Error retrieving user list:', error);
    res.status(500).send('Internal Server Error');
  }
});

app.post('/moderator/ban-user', isAuthenticated, authorizeRole(['admin', 'moderator']), async (req, res) => {
  const { userId } = req.body;

  try {
    await pool.query('UPDATE user1 SET status = $1 WHERE id = $2', ['banned', userId]);
    res.redirect('/moderator');
  } catch (error) {
    console.error('Error banning user:', error);
    res.status(500).send('Internal Server Error');
  }
});

app.post('/moderator/unban-user', isAuthenticated, authorizeRole(['admin', 'moderator']), async (req, res) => {
  const { userId } = req.body;

  try {
    await pool.query('UPDATE user1 SET status = $1 WHERE id = $2', ['active', userId]);
    res.redirect('/moderator');
  } catch (error) {
    console.error('Error unbanning user:', error);
    res.status(500).send('Internal Server Error');
  }
});

// User Route
app.get('/user', isAuthenticated, async (req, res) => {
  const userStatus = req.session.user ? req.session.user.status : null;

  if (userStatus === 'banned') {
    req.session.destroy();
    res.send('Your account has been banned.');
  } else {
    res.sendFile(__dirname + '/user.html');
  }
});


app.listen(port, () => {
  console.log(`Server is running at http://localhost:${port}`);
});
