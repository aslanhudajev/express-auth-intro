import express from "express";
import session from "express-session";
import passport from "passport";
import { Strategy as LocalStrategy } from "passport-local";
import bcrypt from "bcryptjs";
import "dotenv/config";
import mongoose from "mongoose";
const Schema = mongoose.Schema;

await mongoose
  .connect(process.env.MDB_CONNECTION_STR, {
    dbName: process.env.DB_NAME,
  })
  .then(() => console.log("MDB connection successfull"))
  .catch((error) => console.log(error));

const UserSchema = new Schema({
  username: { type: String, required: true },
  password: { type: String, required: true },
});
const User = mongoose.model("User", UserSchema);

const app = express();
app.set("views", "./views");
app.set("view engine", "pug");

passport.use(
  new LocalStrategy(async (username, password, done) => {
    try {
      const user = await User.findOne({ username: username });

      if (!user) {
        return done(null, false, { message: "Wrong username or password" });
      } else {
        const passwordMatch = bcrypt.compare(password, user.password);
        if (!passwordMatch) {
          return done(null, false, { message: "Wrong username or password" });
        }
      }

      return done(null, user);
    } catch (error) {
      return done(error);
    }
  }),
);

passport.serializeUser((user, done) => {
  done(null, user._id);
});

passport.deserializeUser(async (id, done) => {
  try {
    const user = await User.findOne({ _id: id });
    done(null, user);
  } catch (error) {
    done(error);
  }
});

app.use(session({ secret: "cats", resave: false, saveUninitialized: true }));
app.use(passport.session());
app.use(express.static("./public"));
app.use(express.json());
app.use(express.urlencoded({ extended: false }));

app.get("/", (req, res, next) => res.render("index", { user: req.user }));

app.get("/signup", (req, res, next) => res.render("signup"));
app.post("/signup", async (req, res, next) => {
  bcrypt.hash(req.body.password, 10, async (error, hashedPassword) => {
    if (error) {
      return next(error);
    } else {
      try {
        const newUser = new User({
          username: req.body.username,
          password: hashedPassword,
        });

        await newUser.save();
        res.redirect("/");
      } catch (error) {
        return next(error);
      }
    }
  });
});

app.get("/signin", (req, res, next) => res.render("signin"));
app.post(
  "/signin",
  passport.authenticate("local", {
    successRedirect: "/",
    failureRedirect: "/signin",
  }),
);

app.get("/signout", (req, res, next) => {
  req.logout((error) => {
    if (error) {
      return next(error);
    } else {
      res.redirect("/");
    }
  });
});
app.listen(3000, () => console.log("Server started and listeing to port 3000"));
