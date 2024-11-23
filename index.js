
const express = require('express');
const bodyParser = require('body-parser');
const path = require('path');
const multer= require('multer');
const pg = require('pg');
const bcrypt = require("bcrypt");
const session = require("express-session");
const passport = require("passport");
const { Strategy } = require("passport-local");


const app = express();
const PORT = 3000;
const saltRound = 10;

const db = new pg.Client({
  user: 'postgres',
  host: 'localhost',
  database: 'Data',
  password: 'postgres',
  port: 5432,

});
db.connect();

app.use(bodyParser.urlencoded({ extended: true }));
app.use(express.static("public"));
app.set("view engine", "ejs");

app.use(session({
  secret: "PasswordKey",
  resave: false,
  saveUninitialized: true,
  cookie:{
    maxAge: 1000 * 60 * 60 * 24
  }
}));

app.use(passport.initialize());
app.use(passport.session());

let posts= [];

db.query('SELECT * FROM posts', (error, result)=>{
  if(error){
    console.error("Error fetching posts:" , error);
  } else{
    posts= result.rows;
  }
})


const storage = multer.diskStorage({
  destination: "./public/images",
  filename: function (req, file, cb) {
    cb(null, Date.now() + path.extname(file.originalname));
  },
});


const upload = multer({
  storage: storage,
  limits: { fileSize: 1000000 }, 
}).single("imageUrl");



app.get("/dashboard", (req,res)=>{
  if(req.isAuthenticated()){
    res.render("dashboard",{posts})
  }
  else{
    res.redirect("/login")
  }
})

app.get("/", (req, res)=>{
  res.render("home");
});

app.get("/login", (req, res)=>{
  res.render("login");
});

app.get("/signup", (req, res)=>{
  res.render("signup");
});

app.get("/newpost", (req, res) => {
  res.render("newpost");
});

app.post("/register", async (req,res)=>{
  const name = req.body.name;
  const email= req.body.email;
  const password= req.body.password;

  try{
    const checkResult= await db.query("SELECT * FROM users WHERE email = $1",[email]);
     if(checkResult.rows.length > 0){
      res.send("You are already registered!");
     }
     else{
      bcrypt.hash(password, saltRound, async (err, hash)=>{
        const result= await db.query("INSERT INTO users (name, email, password) VALUES ($1,$2,$3) RETURNING *",[name,email,hash]);
        const user= result.rows[0];
        
        req.logIn(user,(err)=>{
          if(err){
            console.log(err);
          }
          res.redirect("/dashboard");
        })
      });
     }

  }
  catch (err){
    console.log(err);
  }
});


app.post("/login",passport.authenticate("local",{
  successRedirect: "/dashboard",
  failureRedirect:"/login"
}));



app.post("/newpost", (req, res) => {
  upload(req, res, (err) => {
    if (err) {
      console.error(err);
      // Handle error
    } else {
      const { title, description } = req.body;
      const imageUrl = req.file ? `/images/${req.file.filename}` : null;
      
      db.query('INSERT INTO posts (title, description, imgurl) VALUES ($1, $2, $3)',[ title, description, imageUrl ]);

     
      res.redirect("/dashboard");
    }
  });
});





app.post("/delete/:id", (req, res) => {
  const postId = parseInt(req.params.id);
  posts = posts.filter((post) => post.id !== postId);

  db.query('DELETE FROM posts WHERE id = $1', [postId]);

  res.render("dashboard",{posts});
});

passport.use(new Strategy(async function verify(username,password,cb){
  try{
    const result = await db.query("SELECT * FROM users WHERE email = $1",[username,]);
     if(result.rows.length>0){
      const user = result.rows[0];
      const dbPassword = user.password;
      bcrypt.compare(password,dbPassword,(err,result)=>{
        if(result){
          return cb(null,user);
        }
        else{
          return cb(null,false);
        }
      });
    }
    else{
      return cb("User is not found!");
    }
  } catch(err){
    return cb(err);
  }
}))

passport.serializeUser((user,cb)=>{
  cb(null,user);
})

passport.deserializeUser((user,cb)=>{
  cb(null,user);
})

app.listen(PORT, () => {
  console.log(`Server is running  on port ${PORT}`);
});
