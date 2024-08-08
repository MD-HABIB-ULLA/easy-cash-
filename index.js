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


const { MongoClient, ServerApiVersion, ObjectId, Transaction } = require('mongodb');
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
    const pendingTransition = client.db("easycash").collection("pendingTransitions")
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

    // registration related api---------------------------------------------

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

    // login related api------------------------------------------------------
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

    // all transitions for admin-----------------------------------------------
    app.get('/allTransitions', verifytoken, verifyAdmin, async (req, res) => {
      const result = await allTransitions.find().toArray()
      res.send(result)
    })







    // user approve related apis----------------------------------------------------- 
    const getAdminDataByEmail = async (email) => {
      return await userCollection.findOne({ email });
    };

    app.delete("/approve", verifytoken, verifyAdmin, async (req, res) => {
      try {
        const { id, pin, email } = req.query;
        console.log(id, pin, email);

        if (!id || !pin || !email) {
          return res.status(400).send('Missing required parameters');
        }

        // Get admin data
        const adminData = await getAdminDataByEmail(email);
        if (!adminData) {
          return res.status(404).send('User not found');
        }

        // Validate PIN
        const isPinValid = await bcrypt.compare(pin, adminData.pin);
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
        if (role === "agent") {
          pendingUser.balance = 10000;
        } else {
          pendingUser.balance = 40;
        }
        delete pendingUser.appliedRole;

        // Add pending user to user collection
        const addUserResult = await userCollection.insertOne(pendingUser);
        if (!addUserResult.acknowledged) {
          throw new Error('Failed to add user to collection');
        }

        // Remove pending user from pending collection
        const deletePendingUserResult = await pendingUserCollection.deleteOne({ _id: new ObjectId(id) });
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

    // delete user from pending data base ------------------------------------------

    app.delete('/deleteUser', async (req, res) => {
      const { id, pin, email } = req.query
      console.log(id, pin, email)


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
      const result = await pendingUserCollection.deleteOne({ _id: new ObjectId(id) });
      res.send(result)
    })


    //  all user data ------------------------------------------------------------
    app.get("/alluser", verifytoken, verifyAdmin, async (req, res) => {
      const users = await userCollection.find().toArray()
      const pendingUsers = await pendingUserCollection.find().toArray()
      res.send({ users, pendingUsers })
    })

    //  load all agent details -----------------------------------------------
    app.get("/allAgent", async (req, res) => {
      const result = await userCollection.find({ role: "agent" }).toArray()
      res.send(result)
    })

    // post cash in details ---------------------------------------

    app.post("/cashIn", async (req, res) => {
      const data = req.body
      const agentEmail = req.body.agentEmail
      const agentPhoneNumber = data.phoneNumber
      let query
      if (agentEmail) {
        query = {
          email: agentEmail,
          role: "agent"

        }
      } else {
        query = {
          phoneNumber: agentPhoneNumber,
          role: "agent"
        }
      }


      // identify is there any cash in request exist in data base to this user 

      const existingRequest = await pendingTransition.findOne({ userEmail: data.userEmail, type: "cashIn" });
      if (existingRequest) {
        return res.status(400).json({ error: 'A cash-in request has already been made for this user.' });
      }

      // validate the agent details 
      const validateAgent = await userCollection.findOne(query)
      if (!validateAgent) {
        return res.status(400).json({ error: 'please enter valid agent details ' });
      }

      const result = await pendingTransition.insertOne(data)
      console.log(data)
      res.send(result)
    })


    //  pending transitions  requests --------------------------------------------------
    app.get("/pendingTransitions", async (req, res) => {
      const { email } = req.query
      console.log(email)
      const result = await pendingTransition.find({ userEmail: email }).toArray()
      res.send(result)
    })
    app.delete("/deletePendingTransition", async (req, res) => {
      const { email, pin, id } = req.query

      // find the user throw email
      const userData = await userCollection.findOne({ email: email })
      if (!userData) {
        return res.status(404).send('User not found');
      }

      const isPinValid = await bcrypt.compare(pin, userData.pin);
      if (!isPinValid) {
        return res.status(401).send('Invalid PIN');
      }

      const result = await pendingTransition.deleteOne({ _id: new ObjectId(id) })

      // console.log(email, pin, id)
      res.send(result)
    })



    // cash out api ------------------------------------------------------------
    app.post("/cashOut", verifytoken, async (req, res) => {
      const data = req.body
      const email = data.userEmail
      const pin = data.pin
      const amount = data.amount
      const agentEmail = data.agentEmail
      const agentPhoneNumber = data.phoneNumber
      if (amount) {
        data.fee = amount * 0.015
      }
      let query
      if (agentEmail) {
        query = {
          email: agentEmail,
          role: "agent"

        }
      } else {
        query = {
          phoneNumber: agentPhoneNumber,
          role: "agent"
        }
      }


      // identify is there any cash out request is pending in data base 
      const existingRequest = await pendingTransition.findOne({ userEmail: email, type: "cashOut" });
      if (existingRequest) {
        return res.status(400).json({ error: 'A cash-out request has already been made for this user.' });
      }

      // validate the agent details 
      const validateAgent = await userCollection.findOne(query)
      if (!validateAgent) {
        return res.status(400).json({ error: 'please enter valid agent details ' });
      }

      // Validate PIN

      const getUserDataByEmail = async (email) => {
        return await userCollection.findOne({ email });
      };

      const userData = await getUserDataByEmail(email);
      if (!userData) {
        return res.status(404).send('User not found');
      }
      const isPinValid = await bcrypt.compare(pin, userData.pin);
      if (!isPinValid) {
        return res.status(401).send('Invalid PIN');
      }
      delete data.pin;

      console.log(data)
      const result = await pendingTransition.insertOne(data)


      res.send(result)
    })

    // send money api -=----------------------------------------------------------g
    app.post("/sendMoney", verifytoken, async (req, res) => {
      const data = req.body
      const email = data.userEmail
      const pin = data.pin
      const amount = data.amount
      const receiverEmail = data.receiverEmail
      const receiverPhoneNumber = data.phoneNumber
      if (amount >= 100) {
        data.fee = 5
      }
      // console.log(data)
      // find the user who send the money 
      const userData = await userCollection.findOne({ email: email })
      if (!userData) {
        return res.status(404).send('User not found');
      }

      //  find the receiver through email & phone number, who receive the money 
      let receiverData;
      if (receiverEmail) {
        receiverData = await userCollection.findOne({ email: receiverEmail });
        if (!receiverData) {
          return res.status(404).send('Receiver is not valid.');
        }
      } else {
        receiverData = await userCollection.findOne({ phoneNumber: receiverPhoneNumber });
        if (!receiverData) {
          return res.status(404).send('Receiver is not valid.');
        }
      }

      // Validate PIN
      const isPinValid = await bcrypt.compare(pin, userData.pin);
      if (!isPinValid) {
        return res.status(401).send('Invalid PIN');
      }

      // Deduct the amount from the sender's balance
      try {
        await userCollection.updateOne(
          { _id: userData._id },
          { $inc: { balance: -(amount >= 100 ? amount + 5 : amount) } }
        );
      } catch (error) {
        return res.status(500).send('Failed to deduct amount from sender');
      }

      // Add the amount to the receiver's balance
      try {
        await userCollection.updateOne(
          { _id: receiverData._id },
          { $inc: { balance: amount } }
        );
      } catch (error) {
        // Rollback sender's balance update in case of failure
        await userCollection.updateOne(
          { _id: userData._id },
          { $inc: { balance: amount } }
        );
        return res.status(500).send('Failed to credit amount to receiver');
      }

      const result = await allTransitions.insertOne(data)


      // console.log(email, pin, amount)
      res.send(result)
    })

    //  get all the transaction of an user 
    app.get("/userSelfTransaction", verifytoken, async (req, res) => {
      const { email } = req.query
      // console.log(email)
      const result = await allTransitions.find({ userEmail: email }).toArray()
      res.send(result)
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


