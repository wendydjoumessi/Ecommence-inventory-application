const dotenv = require("dotenv").config();
const express = require("express");
const mongoose = require("mongoose");
const bodyparser = require("body-parser");
const cors = require("cors");
const UserRoute = require("./routes/UserRoute");
const User = require("./models/UserModel");
const errorHandler = require("./middleWare/errorMiddleware");
const cookieParser = require("cookie-parser")
const app = express();

// Middlewares
app.use(express.json());
app.use(cookieParser());
app.use(express.urlencoded({ extended: false }));
app.use(bodyparser.json());
app.use(cors());

//Route Middleware
app.use("/api/Users", UserRoute);

//Routes
app.get("/", (req, res) => {
  res.send("Home Page");
});

// Error MiddleWare
app.use(errorHandler);

const Port = process.env.Port || 3000;

// connect to DB and start server
mongoose
  .connect(process.env.MONGO_URI)
  .then(() => {
    app.listen(Port, () => {
      console.log(`Server Running on port ${Port}`); //connecting to the server
    });
  })
  .catch((err) => console.log(err));
