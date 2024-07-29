const express = require('express')
const app = express()
const cors = require('cors');
const port = process.env.PORT || 4000;
const jwt = require('jsonwebtoken')
const bcrypt = require('bcryptjs');

require('dotenv').config()
app.use(cors({
  origin: [
    'http://localhost:5173',
  ],
  credentials: true
}));
app.use(express.json())


const { MongoClient, ServerApiVersion, ObjectId } = require('mongodb');
const uri = `mongodb+srv://${process.env.DB_USER}:${process.env.DB_PASS}@cluster0.zqymdgy.mongodb.net/?retryWrites=true&w=majority&appName=Cluster0`;

// Create a MongoClient with a MongoClientOptions object to set the Stable API version
const client = new MongoClient(uri, {
  serverApi: {
    version: ServerApiVersion.v1,
    strict: true,
    deprecationErrors: true,
  }
});

async function run() {
  try {

    const pendingUserCollection = client.db("easycash").collection("pendingUsers")
    const userCollection = client.db("easycash").collection("users")
    const allTransitions = client.db("easycash").collection("transitions")
    // Connect the client to the server	(optional starting in v4.7)
    // await client.connect();
    // Send a ping to confirm a successful connection

    const verifytoken = (req, res, next) => {
      // console.log('inside verify token', req.headers.authorization);
      if (!req.headers.authorization) {
        return res.status(401).send({ message: 'unauthorized access' });
      }
      const token = req.headers.authorization.split(' ')[1];
      jwt.verify(token, process.env.ACCESS_TOKEN_SECRET, (err, decoded) => {
        if (err) {
          return res.status(401).send({ message: 'unauthorized access' })
        }
        req.decoded = decoded;

        next();
      })
    }


    const verifyAdmin = async (req, res, next) => {
      const email = req.decoded.email;
      const query = { email: email };
      const user = await userCollection.findOne(query);
      const isAdmin = user?.role === 'admin';
      if (!isAdmin) {
        return res.status(403).send({ message: 'forbidden access' });
      }

      next();
    }















    // jwt related api--------------------------------------
    app.post('/jwt', async (req, res) => {
      const user = req.body;
      const token = jwt.sign(user, process.env.ACCESS_TOKEN_SECRET, { expiresIn: '1h' })
      res.send({ token })
    })

    // registration related api

    app.post("/register", async (req, res) => {
      const userData = req.body;
      const { email, pin } = req.body
      const userExists = await userCollection.findOne({ email });
      if (userExists) {
        return res.status(400).send("User already a valid user , just login.");
      }

      // Check if user exists in PendingUserCollection
      const pendingUserExists = await pendingUserCollection.findOne({ email });
      if (pendingUserExists) {
        return res.status(400).send("please wait until the admin validates your profile ");
      }
      const hashedPin = await bcrypt.hash(pin, 10);
      userData.pin = hashedPin;

      const result = await pendingUserCollection.insertOne(userData)
      res.send(result)
    })

    // login related api
    app.post("/login", async (req, res) => {
      const { email, phoneNumber, pin } = req.body;
      // console.log(email)

      if (!email && !phoneNumber) {
        return res.status(400).send("Please provide either an email or a phone number.");
      }

      try {
        let userData;

        if (phoneNumber) {
          const query = { phoneNumber: phoneNumber }
          userData = await userCollection.findOne(query);
          // console.log(userData)
        } else if (email) {
          const query = { email: email }
          userData = await userCollection.findOne(query);
          // console.log("email", userData)
        }

        if (!userData) {
          return res.status(400).send("Please create an account first ");
        }

        const isPinValid = await bcrypt.compare(pin, userData.pin);
        if (!isPinValid) {
          return res.status(401).send('Invalid PIN');
        }

        res.send(userData);
      } catch (error) {
        // console.error('Error during login:', error);
        return res.status(400).send("Please create an account first ");
      }

    })







    // user approve related apis 
  app.delete("/approve", async (req, res) => {
  try {
    const { id, pin, email } = req.query;
    console.log(id, pin, email);

    if (!id || !pin || !email) {
      return res.status(400).send('Missing required parameters');
    }

    // Function to get user data by email
    const getUserDataByEmail = async (email) => {
      return await userCollection.findOne({ email });
    };

    // Get user data
    const userData = await getUserDataByEmail(email);
    if (!userData) {
      return res.status(404).send('User not found');
    }

    // Validate PIN
    const isPinValid = await bcrypt.compare(pin, userData.pin);
    if (!isPinValid) {
      return res.status(401).send('Invalid PIN');
    }

    // Get pending user data
    const pendingUser = await pendingUserCollection.findOne({ _id: new ObjectId(id) });
    if (!pendingUser) {
      return res.status(404).send('Pending user not found');
    }

    // Set role and balance
    const role = pendingUser.appliedRole || "user";
    pendingUser.role = role;
    delete pendingUser.appliedRole;
    pendingUser.balance = 40;

    // Create transition details
    const currentDate = new Date();
    const formattedDate = `${currentDate.getDate()}/${currentDate.getMonth() + 1}/${currentDate.getFullYear()}`;
    const transitionDetails = {
      email: pendingUser.email,
      amount: pendingUser.balance,
      from: "admin",
      time: formattedDate
    };

    // Insert transition details
    const transitionResult = await allTransitions.insertOne(transitionDetails);
    if (!transitionResult.acknowledged) {
      throw new Error('Failed to insert transition details');
    }

    // Add pending user to user collection
    const addUserResult = await userCollection.insertOne(pendingUser);
    if (!addUserResult.acknowledged) {
      throw new Error('Failed to add user to collection');
    }

    // Remove pending user from pending collection
    const deletePendingUserResult = await pendingUserCollection.deleteOne({ email: pendingUser.email });
    if (!deletePendingUserResult.acknowledged) {
      throw new Error('Failed to delete pending user');
    }

    // Send success response
    res.send(deletePendingUserResult);

  } catch (error) {
    console.error("Error approving user:", error);
    res.status(500).send('Internal server error');
  }
});


    app.get("/alluser", verifytoken, verifyAdmin, async (req, res) => {
      const users = await userCollection.find().toArray()
      const pendingUsers = await pendingUserCollection.find().toArray()
      res.send({ users, pendingUsers })
    })
    app.get('/', (req, res) => {
      res.send('Hello World!')
    })

    app.listen(port, () => {
      console.log(`Example app listening on port ${port}`)
    })
    await client.db("admin").command({ ping: 1 });
    console.log("Pinged your deployment. You successfully connected to MongoDB!");
  } finally {
    // Ensures that the client will close when you finish/error
    // await client.close();
  }
}
run().catch(console.dir);


