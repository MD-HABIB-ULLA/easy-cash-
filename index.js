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


const { MongoClient, ServerApiVersion } = require('mongodb');
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

    const PendingUserCollection = client.db("easycash").collection("pendingUsers")
    const userCollection = client.db("easycash").collection("users")
    // Connect the client to the server	(optional starting in v4.7)
    // await client.connect();
    // Send a ping to confirm a successful connection
    // jwt related api--------------------------------------
    app.post('/jwt', async (req, res) => {
      const user = req.body;
      const token = jwt.sign(user, process.env.ACCESS_TOKEN_SECRET, { expiresIn: '1h' })
      res.send({ token })
    })

    app.post("/register", async (req, res) => {
      const userData = req.body;
      const { email, pin } = req.body
      const userExists = await userCollection.findOne({ email });
      if (userExists) {
        return res.status(400).send("User already a valid user , just login.");
      }

      // Check if user exists in PendingUserCollection
      const pendingUserExists = await PendingUserCollection.findOne({ email });
      if (pendingUserExists) {
        return res.status(400).send("please wait until the admin validates your profile ");
      }
      const hashedPin = await bcrypt.hash(pin, 10);
      userData.pin = hashedPin;

      const result = await PendingUserCollection.insertOne(userData)
      res.send(result)
    })


    app.post("/login", async (req, res) => {
      const { email, phoneNumber, pin } = req.body;
      console.log(email)

      if (!email && !phoneNumber) {
        return res.status(400).send("Please provide either an email or a phone number.");
      }

      try {
        let userData;

        if (phoneNumber) {
          const query = { phoneNumber: phoneNumber }
          userData = await userCollection.findOne(query);
          console.log(userData)
        } else if (email) {
          const query = { email: email }
          userData = await userCollection.findOne(query);
          console.log("email", userData)
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
        console.error('Error during login:', error);
        return res.status(400).send("Please create an account first ");
      }

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


