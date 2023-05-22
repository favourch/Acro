const express = require('express');
const router = express.Router();
const jwt = require('jsonwebtoken');
const session = require('express-session');
const db = require('../inc/database');

router.use(session({ secret: process.env.SESSION_SECRET, resave: false, saveUninitialized: true }));

async function getUserData(token) {
  const decoded = jwt.verify(token, process.env.JWT_SECRET);
  const email = decoded.email;
  const userID = decoded.userID;

  // SQL Query to get the user details
  const [rows] = await db.execute('SELECT * FROM users WHERE email = ?', [email]);
  if (rows.length === 0) {
    throw new Error('User not found');
  }

  // SQL Query to get all licenses for the user
  const [licenses] = await db.execute('SELECT * FROM trading_accounts WHERE user_id = ?', [userID]);
  
  // SQL Query to get all transactions for the user
  const [transactions] = await db.execute('SELECT * FROM transactions WHERE user_id = ?', [userID]);


  // Fetch all users in the database that were referred by the current user
  const [refrows] = await db.execute('SELECT * FROM users WHERE referral_number = ?', [userID]);

  

  return {
    user: {
      user_id: rows[0].user_id,
      email: rows[0].email,
      fname: rows[0].fname,
      lname: rows[0].lname,
      phone: rows[0].phone,
    },
    licenses,
    transactions,
    refrows,
  };
}

router.get('/dashboard', async (req, res) => {
  const token = req.session.token;

  let message = ''; // Define an empty message initially
  
  if (!token) {
    return res.render('./user/login', { message: 'Unauthorized Access. Please login again' });
  }

  try {
    const userData = await getUserData(token);
    return res.render('./user/dashboard', userData);
  } catch (error) {
    console.error(error);
    return res.render('./user/login', { message: 'Session expired. Please login again' });
  }
});

router.get('/profile', async (req, res) => {
  const token = req.session.token;
  if (!token) {
    return res.render('./user/login', { message: 'Unauthorized Access. Please login again' });
  }

  try {
    const userData = await getUserData(token);
    return res.render('./user/profile', userData);
  } catch (error) {
    console.error(error);
    return res.render('./user/login', { message: 'Session expired. Please login again' });
  }
});

router.get('/transactions', async (req, res) => {
  const token = req.session.token;
  if (!token) {
    return res.render('./user/login', { message: 'Unauthorized Access. Please login again' });
  }

  try {
    const userData = await getUserData(token);
    return res.render('./user/transactions', userData);
  } catch (error) {
    console.error(error);
    return res.render('./user/login', { message: 'Session expired. Please login again' });
  }
});




// Check License
router.post('/check-licenses', async (req, res) => {
    const token = req.session.token;
    if (!token) {
        return res.status(401).send('Unauthorized Access. Please login again');
    }

    try {
        const decoded = jwt.verify(token, process.env.JWT_SECRET);
        const userID = decoded.userID;

        // SQL Query to get all licenses for the user
        const [licenses] = await db.execute('SELECT * FROM trading_accounts WHERE user_id = ?', [userID]);

        // Check if the user already has 3 licenses
        if (licenses.length >= 3) {
            return res.status(400).send('You have reached the maximum number of licenses for this account');
        }

        // If the user is allowed to add more licenses, return a success message
        return res.status(200).send('Success');
    } catch (error) {
        console.error(error);
        return res.status(500).send('An error occurred. Please try again later');
    }
});

// Add a new license
router.post('/add-license', async (req, res, next) => {
  const token = req.session.token;
  if (!token) {
    return res.status(401).send('Unauthorized Access. Please login again');
  }

  try {
    // Extract license information from the request body
    const { metaTraderNo, tradingServerName } = req.body;

    // Validate input
    if (!metaTraderNo || !tradingServerName) {
      // const error = new Error('Missing license information');
      return res.render('./user/login', { message: 'Missing license information' });
      // error.statusCode = 400;
      // throw error;
    }

    // Decode the JWT to get the user ID
    const decoded = jwt.verify(token, process.env.JWT_SECRET);
    const userID = decoded.userID;

    // SQL Query to insert the new license into the database
    const [result] = await db.execute('INSERT INTO trading_accounts (user_id, meta_trader_no, trading_server_name) VALUES (?, ?, ?)', [
      userID,
      metaTraderNo,
      tradingServerName
    ]);

    // If the query is successful, return a success message
    return res.redirect('/dashboard');
  } catch (error) {
    console.error(error);
    error.message = 'Error adding license';
    return next(error);
  }
});


router.get('/referrals', async (req, res) => {
    const token = req.session.token;

    if (!token) {
        return res.render('./user/login', { message: 'Unauthorized Access. Please login again' });
    }

    try {
        // Decode the JWT to get the user ID
        const decoded = jwt.verify(token, process.env.JWT_SECRET);
        const userID = decoded.userID;

        // Fetch all users in the database that were referred by the current user
        const [rows] = await db.execute('SELECT * FROM users WHERE referral_number = ?', [userID]);

        // Create a map to store users at their respective levels in the referral tree
        const referralTree = {};

        // Add the referred users to their levels in the referral tree
        rows.forEach(row => {
            const { user_id, referral_number } = row;

            let newUser = { user: row, children: [] };
            referralTree[user_id] = newUser;

            let parent = referralTree[referral_number];
            if (!parent) {
                parent = { user: null, children: [] };
                referralTree[referral_number] = parent;
            }

            parent.children.push(newUser);
        });

        // Define an empty tree view initially
        let treeView = '';

        // Function to recursively build the tree view from the referral tree
        const buildTreeView = (node) => {
            let result = '';
            if (node.user) {
                // Define an icon for each referral using Bootstrap classes
                const icon = node.user.user_id === userID ? 'fas fa-user-shield' : 'fas fa-user-alt';

                // Append the email of the referral to the icon
                const email = node.user.user_id;

                // Build the HTML for this node in the tree view
                result += `<li><span><i class="${icon}"></i> ${email}</span>`;
            }

            if (node.children.length > 0) {
                // Recursively build the subtree for each child and append it to the current node
                result += '<ul>';
                node.children.forEach(child => {
                    result += buildTreeView(child);
                });
                result += '</ul>';
            }

            if (node.user) {
                // Close the HTML tag for this node
                result += '</li>';
            }

            return result;
        };

        // Build the tree view from the root of the referral tree
        if (referralTree[userID]) {
            treeView = `<ul>${buildTreeView(referralTree[userID])}</ul>`;
        }

        // Render the referral view with the referral tree
        // res.render('./user/referral', { referralTree, treeView });
        res.render('./user/referral', { referralTree, treeView, userID });
        
    } catch (error) {
        console.error(error);
        return res.render('./user/login', { message: 'Session expired. Please login again' });
    }
});







module.exports = router;
