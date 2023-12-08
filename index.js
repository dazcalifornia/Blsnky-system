// Import required modules
const express = require("express");
const bcrypt = require("bcrypt");
const jwt = require("jsonwebtoken");
const mysql = require("mysql");
const bodyParser = require("body-parser");
const multer = require("multer");
const path = require("path");
const cors = require("cors");
const fs = require("fs");

const { v4: uuidv4 } = require("uuid");

// Create an Express app
const app = express();

const corsOptions = {
  origin: "https://your-react-app-domain.com", // Replace with your React app's domain
  methods: "GET,HEAD,PUT,PATCH,POST,DELETE",
  credentials: true, // Allow credentials (e.g., cookies)
  optionsSuccessStatus: 204,
};

app.use(cors(corsOptions));

app.use(bodyParser.json());

app.use(express.static("public"));

app.use("/uploads", express.static("uploads"));

// MySQL configuration
const db = mysql.createConnection({
  host: "localhost",
  user: "root",
  password: "",
  database: "jin",
});

function connectToDatabase() {
  db.connect((err) => {
    if (err) {
      console.error("Error connecting to the database:", err);
      console.log("Retrying in 5 seconds...");
      setTimeout(connectToDatabase, 5000); // Retry after 5 seconds
    } else {
      console.log("Connected to MySQL database");
    }
  });
}

// Initialize the database connection
connectToDatabase();

function generateUniqueId() {
  return uuidv4();
}

// Secret key for JWT
const secretKey =
  "UycW7mRYLGi8cNzOVj605bb2rywVA610uvb6iuLK5Jyoo9g/pTuit2hZ87nlSESykf16cDaUAuVhAJ/H";

// In-memory token blacklist
const invalidTokens = new Set(); // Registration endpoint

const postStorage = multer.diskStorage({
  destination: function (req, file, cb) {
    const userId = req.user.userId; // Get user ID from JWT token
    const destinationPath = path.resolve(
      __dirname,
      "uploads",
      "posts",
      `${userId}`
    );

    // Check if the directory exists, and create it if it doesn't
    if (!fs.existsSync(destinationPath)) {
      fs.mkdirSync(destinationPath, { recursive: true });
    }

    cb(null, destinationPath);
  },
  filename: function (req, file, cb) {
    const uniqueSuffix = Date.now() + "-" + Math.round(Math.random() * 1e9);
    cb(null, uniqueSuffix + "-" + file.originalname);
  },
});

const uploadPost = multer({ storage: postStorage });

const profileStorage = multer.diskStorage({
  destination: function (req, file, cb) {
    const userId = req.user.userId; // Get user ID from JWT token
    console.log("User ID:", userId);
    const destinationPath = path.resolve(
      __dirname,
      "uploads",
      "profiles",
      `${userId}`
    );
    if (!fs.existsSync(destinationPath)) {
      fs.mkdirSync(destinationPath, { recursive: true });
    }
    console.log("Destination Path:", destinationPath);
    cb(null, destinationPath);
  },
  filename: function (req, file, cb) {
    const uniqueSuffix = Date.now() + "-" + Math.round(Math.random() * 1e9);
    cb(null, uniqueSuffix + "-" + file.originalname);
  },
});

const uploadProfile = multer({ storage: profileStorage });

const assignmentSubmissionStorage = multer.diskStorage({
  destination: (req, file, cb) => {
    // Set the destination path for uploaded files
    const userId = req.user.userId; // Get user ID from JWT token
    const destinationPath = path.resolve(
      __dirname,
      "uploads",
      "assignments",
      `${userId}`,
      `${req.params.assignmentId}`
    );

    // Check if the directory exists, and create it if it doesn't
    if (!fs.existsSync(destinationPath)) {
      fs.mkdirSync(destinationPath, { recursive: true });
    }

    cb(null, destinationPath);
  },
  filename: (req, file, cb) => {
    // Set the filename for the uploaded file
    const uniqueSuffix = Date.now() + "-" + Math.round(Math.random() * 1e9);
    cb(null, uniqueSuffix + "-" + file.originalname);
  },
});

// Create an instance of the multer middleware
const uploadAssignment = multer({ storage: assignmentSubmissionStorage });

app.post("/register", (req, res) => {
  const { username, email, password } = req.body;
  console.log("Received Request Body:", req.body); // Log the request body

  // Check if the password is missing or empty
  if (!password) {
    return res.status(400).json({ error: "Password is required" });
  }

  // Hash the password
  bcrypt.hash(password, 10, (err, hash) => {
    if (err) {
      console.error(err);
      return res.status(500).json({ error: "Hashing error" });
    }

    // Create a user object with the hashed password
    const user = {
      username,
      email,
      password: hash, // Store the hashed password in the database
      role: "user",
    };

    // Store the user data in the database
    db.query("INSERT INTO users SET ?", user, (err, results) => {
      if (err && err.code === "ER_DUP_ENTRY") {
        console.error(err);
        return res.status(409).json({ error: "Email already exists" });
      }

      res.status(201).json({ message: "Registration successful" });
    });
  });
});

// Login endpoint
app.post("/login", (req, res) => {
  const { email, password } = req.body;
  console.log("Received email:", email);
  console.log("Received password:", password);

  db.query("SELECT * FROM users WHERE email = ?", [email], (err, results) => {
    if (err) {
      console.error("Login error:", err);
      return res.status(500).json({ error: "Login error" });
    }

    if (results.length === 0) {
      console.error("Invalid credentials: User not found");
      return res.status(401).json({ error: "Invalid credentials" });
    } else {
      console.log("User found");
    }

    const user = results[0];

    bcrypt.compare(password, user.password, (err, isMatch) => {
      if (err) {
        console.error("Password comparison error:", err);
        return res.status(500).json({ error: "Login error" });
      }

      if (!isMatch) {
        console.error("Invalid credentials: Password does not match");
        return res.status(401).json({ error: "Invalid credentials" });
      }

      // If credentials are valid, create a JWT
      const token = jwt.sign({ userId: user.id, role: user.role }, secretKey, {
        expiresIn: "7d", // Token expiration time
      });
      //make const of expiration token
      const expirationTime = jwt.decode(token).exp;
      // Attach the user info to the request object
      req.user = { userId: user.id, role: user.role };

      console.log("User role:", req.user.role);
      res.status(200).json({ token, expirationTime });
    });
  });
});

// Create a new post endpoint with optional file uploads

app.post(
  "/post",
  requireAuthentication,
  uploadPost.array("files", 5),
  (req, res) => {
    const { title, content } = req.body;
    const userId = req.user.userId; // Get user ID from JWT token
    console.log("Received Request Body:", req.body); // Log the request body

    if (!title) {
      return res.status(400).json({ error: "Title is required" });
    }

    // Access the uploaded file information
    const files = req.files;

    // Create a comma-separated string of file names (or paths)
    const fileNames = files ? files.map((file) => file.filename).join(",") : "";

    // Update the path to include the user_id
    const post = {
      title,
      content: content || "",
      user_id: userId,
      files: fileNames,
    };

    db.query("INSERT INTO posts SET ?", post, (err, results) => {
      if (err) {
        console.error(err);
        return res.status(500).json({ error: "Post creation error" });
      }

      res.status(201).json({ message: "Post created successfully" });
    });
  }
);

// Get all posts endpoint
app.get("/posts", (req, res) => {
  db.query("SELECT * FROM posts", (err, results) => {
    if (err) {
      return res.status(500).json({ error: "Error fetching posts" });
    }

    // Modify each post to include images and files as arrays
    const postsWithImagesAndFiles = results.map((post) => {
      if (post.images) {
        post.images = post.images.split(",");
      } else {
        post.images = [];
      }

      if (post.files) {
        // Split files string into an array
        const fileArray = post.files.split(",");

        // Filter images and other files
        post.images = fileArray.filter((file) =>
          /\.(gif|jpg|jpeg|png)$/i.test(file)
        );
        post.files = fileArray.filter(
          (file) => !/\.(gif|jpg|jpeg|png)$/i.test(file)
        );
      } else {
        post.images = [];
        post.files = [];
      }

      return post;
    });

    res.status(200).json(postsWithImagesAndFiles);
  });
});

// Logout endpoint
app.post("/logout", requireAuthentication, (req, res) => {
  const token = req.headers.authorization.replace("Bearer ", "");

  // Add the token to the blacklist (in-memory)
  invalidTokens.add(token);

  res.status(200).json({ message: "Logout successful" });
});

// Middleware to check for token validity and add user info to req.user
function requireAuthentication(req, res, next) {
  const token = req.headers.authorization; // Assuming the token is included in the "Authorization" header

  if (!token) {
    return res.status(401).json({ error: "Unauthorized: Token missing" });
  }

  jwt.verify(token.replace("Bearer ", ""), secretKey, (err, decoded) => {
    if (err) {
      console.error(err); // Log the error for debugging
      return res.status(401).json({ error: "Token is invalid" });
    }

    console.log("Decoded Token:", decoded); // Log the decoded token for debugging

    req.user = decoded; // Attach the decoded user info to the request object
    next();
  });
}

// Admin-only route using middleware
function requireAdminRole(req, res, next) {
  const token = req.headers.authorization; // Assuming the token is included in the "Authorization" header

  if (!token) {
    return res.status(401).json({ error: "Unauthorized" });
  }

  jwt.verify(token.replace("Bearer ", ""), secretKey, (err, decoded) => {
    if (err) {
      console.error(err); // Log the error for debugging
      return res.status(401).json({ error: "Token is invalid" });
    }

    // Check if the user has the 'admin' role
    if (decoded.role === "admin") {
      next(); // User has the 'admin' role, proceed to the route
    } else {
      res.status(403).json({ error: "Access denied" }); // User does not have the required role
    }
  });
}

app.get("/admin", requireAdminRole, (req, res) => {
  res.json({ message: "Admin route accessed" });
});

// Create or Update User Profile Endpoint
app.post(
  "/profile",
  requireAuthentication,
  uploadProfile.single("profile_picture"),
  (req, res) => {
    const userId = req.user.userId; // Get user ID from JWT token
    const { full_name, bio } = req.body;
    const profile_picture = req.file ? req.file.filename : null; // Get uploaded profile picture filename

    // Check if the user has an existing profile
    db.query(
      "SELECT * FROM profiles WHERE user_id = ?",
      [userId],
      (err, results) => {
        if (err) {
          console.error(err);
          return res
            .status(500)
            .json({ error: "Profile creation/update error" });
        }

        // Prepare the profile data
        const profileData = {
          user_id: userId,
          full_name,
          bio,
          profile_picture,
        };

        if (results.length === 0) {
          // If the user doesn't have a profile, create a new one
          db.query(
            "INSERT INTO profiles SET ?",
            profileData,
            (err, results) => {
              if (err) {
                console.error(err);
                return res
                  .status(500)
                  .json({ error: "Profile creation error" });
              }

              res.status(201).json({ message: "Profile created successfully" });
            }
          );
        } else {
          // If the user already has a profile, update it
          db.query(
            "UPDATE profiles SET ? WHERE user_id = ?",
            [profileData, userId],
            (err, results) => {
              if (err) {
                console.error(err);
                return res.status(500).json({ error: "Profile update error" });
              }

              res.status(200).json({ message: "Profile updated successfully" });
            }
          );
        }
      }
    );
  }
);

//get user profile endpoint
app.get("/profile", requireAuthentication, (req, res) => {
  const userId = req.user.userId; // Get user ID from JWT token
  db.query(
    "SELECT * FROM profiles WHERE user_id = ?",
    [userId],
    (err, results) => {
      if (err) {
        console.error(err);
        return res.status(500).json({ error: "Error fetching profile" });
      }
      //prepare the profile data
      const profileData = {
        full_name: results[0].full_name,
        bio: results[0].bio,
        profile_picture: results[0].profile_picture,
      };
      res.status(200).json(profileData);
    }
  );
});

app.get("/api/user-role", requireAuthentication, (req, res) => {
  const userRole = req.user.role; // Get user role from JWT token
  const uid = req.user.userId;
  res.status(200).json({ role: userRole, uid: uid });
});

function generateInviteCode() {
  const length = 6; // Length of the invite code
  const characters =
    "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789";
  let inviteCode = "";

  for (let i = 0; i < length; i++) {
    const randomIndex = Math.floor(Math.random() * characters.length);
    inviteCode += characters.charAt(randomIndex);
  }

  return inviteCode;
}

//create class
app.post("/api/classrooms", requireAuthentication, (req, res) => {
  const { name } = req.body;
  const userId = req.user.userId; // Get user ID from JWT token
  const userRole = req.user.role; // Get user role from JWT token

  // Check if the user's role is "teacher" or "admin" to create a classroom
  if (userRole !== "teacher" && userRole !== "admin") {
    return res.status(403).json({ error: "Permission denied" });
  }

  // Generate a unique invite code (you can use a function for this)
  const inviteCode = generateInviteCode();

  const classroom = {
    name,
    invite_code: inviteCode,
    user_id: userId,
  };

  db.query(
    "SELECT * FROM classrooms WHERE name = ?",
    [classroom.name],
    (err, results) => {
      if (err) {
        console.error(err);
        return res.status(500).json({ error: "Database error" });
      }

      if (results.length > 0) {
        // Classroom name already exists
        return res.status(400).json({ error: "Classroom name already exists" });
      }

      // Classroom name is unique, proceed with insertion
      db.query("INSERT INTO classrooms SET ?", classroom, (err, results) => {
        if (err) {
          console.error(err);
          return res.status(500).json({ error: "Classroom creation error" });
        }

        db.query(
          "SELECT * FROM classrooms WHERE user_id = ? AND name = ?",
          [userId, name],
          (err, results) => {
            if (err) {
              console.error(err);
              return res
                .status(500)
                .json({ error: "Error fetching classrooms" });
            }

            const classes = results;
            console.log(classes[0].id);
            const feed = {
              id: generateUniqueId(),
              classroom_id: classes[0].id,
              name: classes[0].name + classes[0].id,
            };

            db.query(
              "INSERT INTO classroom_feeds SET ?",
              feed,
              (err, results) => {
                if (err) {
                  console.error(err);
                  return res.status(500).json({
                    error: "Feed creation error",
                    details: err.message,
                  });
                }

                console.log(results);
              }
            );

            res
              .status(200)
              .json({ message: "Classroom created successfully", classes });
          }
        );
      });
    }
  );
});

//get own class
app.get("/api/own-class", requireAuthentication, (req, res) => {
  const userId = req.user.userId;
  db.query(
    "SELECT * FROM classrooms WHERE user_id = ?",
    [userId],
    (err, results) => {
      if (err) {
        console.error(err);
        return res.status(500).json({ error: "Error fetching classrooms" });
      }
      res.status(200).json(results);
    }
  );
});

//join class
app.post("/api/classrooms/join", requireAuthentication, (req, res) => {
  const { inviteCode } = req.body;
  const userId = req.user.userId; // Get user ID from JWT token
  console.log("User ID:", userId);
  console.log("Invite Code:", inviteCode);

  db.query(
    "SELECT * FROM classrooms WHERE invite_code = ?",
    [inviteCode],
    (err, results) => {
      if (err) {
        console.error(err);
        return res.status(500).json({ error: "Joining classroom error" });
      }

      if (results.length === 0) {
        return res.status(404).json({ error: "Classroom not found" });
      }

      const classroom = results[0];

      // Check if the user is already a member of the classroom
      db.query(
        "SELECT * FROM classroom_members WHERE classroom_id = ? AND user_id = ?",
        [classroom.id, userId],
        (err, memberResults) => {
          if (err) {
            console.error(err);
            return res.status(500).json({ error: "Joining classroom error" });
          }

          if (memberResults.length === 0) {
            // User is not a member, so add them to the classroom
            const classroomMember = {
              id: generateUniqueId(),
              classroom_id: classroom.id,
              user_id: userId,
            };

            db.query(
              "INSERT INTO classroom_members SET ?",
              classroomMember,
              (err, results) => {
                if (err) {
                  console.error(err);
                  return res
                    .status(500)
                    .json({ error: "Joining classroom error" });
                }

                res
                  .status(200)
                  .json({ message: "Joined classroom successfully" });
              }
            );
          } else {
            // User is already a member of the classroom
            res
              .status(400)
              .json({ error: "You are already a member of this classroom" });
          }
        }
      );
    }
  );
});
//fecth joined class
app.get("/api/classrooms", requireAuthentication, (req, res) => {
  const userId = req.user.userId; // Get user ID from JWT Token

  try {
    db.query(
      "SELECT * FROM classroom_members WHERE user_id = ?",
      [userId],
      (err, results) => {
        if (err) {
          console.error(err);
          return res.status(500).json({ error: "Classroom retrieval error" });
        }

        const joinedClass = results.map((result) => result.classroom_id);
        res.status(200).json({ joinedClass });
      }
    );
  } catch (err) {
    console.error(err);
    return res.status(500).json({ error: "Classroom retrieval error" });
  }
});

//get class detailed
app.get(
  "/api/classrooms/:classroomId",
  requireAuthentication,
  async (req, res) => {
    const classroomId = req.params.classroomId;
    const userId = req.user.userId;

    console.log("all I need is a little bit of coffee in my life");
    console.log("allData", classroomId, req.user.userId);

    try {
      db.query(
        "SELECT * FROM classrooms WHERE id = ?",
        [classroomId],
        (err, results) => {
          if (err) {
            console.error(err);
            return res.status(500).json({ error: "Classroom not found" });
          }
          const classroom = results[0];
          if (req.user.role === "teacher") {
            db.query(
              "SELECT * FROM classrooms WHERE id = ? AND user_id = ?",
              [classroomId, userId],
              (err, results) => {
                if (err) {
                  console.error(err);
                  return res
                    .status(500)
                    .json({ error: "Classroom can't be fetched" });
                }
                res.status(200).json({ classroom });
              }
            );
          }
          if (req.user.role === "user") {
            db.query(
              "SELECT * FROM classroom_members WHERE classroom_id = ? AND user_id = ?",
              [classroom.id, userId],
              (err, memberResults) => {
                if (err) {
                  console.error(err);
                  return res.status(500).json({ error: "Classroom not found" });
                }

                if (memberResults.length === 0) {
                  return res.status(403).json({ error: "Not a member" });
                }

                res.status(200).json({ classroom });
              }
            );
          }
        }
      );
    } catch (error) {
      console.error("Get classroom details error:", error);
      res.status(500).json({ error: "Failed to get classroom details" });
    }
  }
);
//create classroom feed
app.post(
  "/api/classroom/:classroomId/feeds",
  requireAuthentication,
  (req, res) => {
    const classroomId = req.params.classroomId;
    const { name } = req.body;

    // Check if the user has permission to create a feed
    if (req.user.role !== "teacher" && req.user.role !== "admin") {
      return res.status(403).json({ error: "Permission denied" });
    }

    const feed = {
      classroom_id: classroomId,
      name,
    };

    db.query("INSERT INTO classroom_feeds SET ?", feed, (err, results) => {
      if (err) {
        console.error(err);
        return res
          .status(500)
          .json({ error: "Feed creation error", details: err.message });
      }

      res.status(201).json({ message: "Feed created successfully" });
    });
  }
);

//get feed from classroom
app.get(
  "/api/classrooms/:classroomId/feeds",
  requireAuthentication,
  (req, res) => {
    const classroomId = req.params.classroomId;

    //check where classroom_id is same classroomId
    db.query(
      "SELECT * FROM classroom_feeds WHERE classroom_id = ?",
      [classroomId],
      (err, results) => {
        if (err) {
          console.error(err);
          return res.status(500).json({ error: "Feed retrieval error" });
        }

        res.status(200).json({ results });
      }
    );
  }
);

//get post from feed By Feedid
app.get(
  "/api/classrooms/:classroomId/feeds/:feedId/posts",
  requireAuthentication,
  (req, res) => {
    const feedId = req.params.feedId;

    //check where classroom_id is same classroom_id and feed_id is same feed_id
    db.query(
      "SELECT * FROM classroom_posts WHERE feed_id = ?",
      [feedId],
      (err, results) => {
        if (err) {
          console.error(err);
          return res.status(500).json({ error: "Post retrieval error" });
        }

        res.status(200).json({ results });
      }
    );
  }
);

// Create a Post in a Feed
app.post(
  "/api/classrooms/:classroomId/feeds/:feedId/posts",
  requireAuthentication,
  (req, res) => {
    const classroomId = req.params.classroomId;
    const feedId = req.params.feedId;
    const { content } = req.body;

    // Check if the user is a member of the classroom
    db.query(
      "SELECT * FROM classroom_members WHERE classroom_id = ? AND user_id = ?",
      [classroomId, req.user.userId],
      (err, memberResults) => {
        if (err) {
          console.error(err);
          return res.status(500).json({
            error: "Membership validation error",
            details: err.message,
          });
        }

        // if (memberResults.length === 0 ) {
        //   return res.status(403).json({
        //     error: "Permission denied: Not a member of this classroom",
        //   });
        // }

        const post = {
          id: generateUniqueId(),
          feed_id: feedId,
          user_id: req.user.userId,
          content,
        };

        db.query("INSERT INTO classroom_posts SET ?", post, (err, results) => {
          if (err) {
            console.error(err);
            return res
              .status(500)
              .json({ error: "Post creation error", details: err.message });
          }

          res.status(201).json({ message: "Post created successfully" });
        });
      }
    );
  }
);

// Create Assignment (Teacher Only)
app.post(
  "/api/classrooms/:classroomId/assignments",
  requireAuthentication,
  (req, res) => {
    const classroomId = req.params.classroomId;
    const { title, description, scheduled_submission, max_score } = req.body;

    // Ensure that the user creating the assignment is a teacher
    if (req.user.role !== "teacher") {
      return res.status(403).json({
        error: "Permission denied: Only teachers can create assignments",
      });
    }

    const assignment = {
      id: generateUniqueId(),
      classroom_id: classroomId,
      title,
      description,
      scheduled_submission,
      max_score,
    };

    db.query("INSERT INTO assignments SET ?", assignment, (err, results) => {
      if (err) {
        console.error(err);
        return res
          .status(500)
          .json({ error: "Assignment creation error", details: err.message });
      }

      res.status(201).json({ message: "Assignment created successfully" });
    });
  }
);

// List Assignments in a Classroom (Teacher and Student)
app.get(
  "/api/classrooms/:classroomId/assignments",
  requireAuthentication,
  (req, res) => {
    const classroomId = req.params.classroomId;

    if (req.user.role === "teacher") {
      db.query(
        "SELECT * FROM classrooms WHERE id = ? AND user_id = ?",
        [classroomId, req.user.userId],
        (err, ownClasses) => {
          if (err) {
            console.error(err);
            return res
              .status(500)
              .json({ error: "Membership validation error" });
          }

          if (ownClasses.length === 0) {
            return res.status(403).json({
              error: "Permission denied: Not a member of this classroom",
            });
          }

          db.query(
            "SELECT * FROM assignments WHERE classroom_id = ?",
            [classroomId],
            (err, assignmentResults) => {
              if (err) {
                console.error(err);
                return res
                  .status(500)
                  .json({ error: "Assignment retrieval error" });
              }

              res.status(200).json({ assignments: assignmentResults });
              console.log("assignment:", assignmentResults);
            }
          );
        }
      );
    }

    if (req.user.role === "user") {
      db.query(
        "SELECT * FROM classroom_members WHERE classroom_id = ? AND user_id = ?",
        [classroomId, req.user.userId],
        (err, memberResults) => {
          if (err) {
            console.error(err);
            return res
              .status(500)
              .json({ error: "Membership validation error" });
          }

          if (memberResults.length === 0) {
            return res.status(403).json({
              error: "Permission denied: Not a member of this classroom",
            });
          }

          db.query(
            "SELECT * FROM assignments WHERE classroom_id = ?",
            [classroomId],
            (err, assignmentResults) => {
              if (err) {
                console.error(err);
                return res
                  .status(500)
                  .json({ error: "Assignment retrieval error" });
              }

              res.status(200).json({ assignments: assignmentResults });
              console.log("assignment:", assignmentResults);
            }
          );
        }
      );
    }

    // Check if the user is a member of the classroom
  }
);

// List Submitted Assignments in a Classroom each assignment (user)
app.get(
  "/api/classrooms/assignments/:assignmentId",
  requireAuthentication,
  (req, res) => {
    const assignmentId = req.params.assignmentId;
    const userId = req.user.userId;

    if (req.user.role === "user" || req.user.role === "teacher") {
      db.query(
        "SELECT * FROM assignment_submissions WHERE user_id = ? and assignment_id = ?",
        [userId, assignmentId],
        (err, submissionResult) => {
          if (err) {
            console.error(err);
            return res
              .status(500)
              .json({ error: "Submission retrieval error" });
          }
          res.status(200).json({ submissions: submissionResult });
          console.log("submission", submissionResult);
        }
      );
    }
  }
);

//list all submitted Assignments in classroom
app.get(
  "/api/classrooms/assignments/:classroomId",
  requireAuthentication,
  (req, res) => {
    const classroomId = req.params.classroomId;
    const userId = req.user.userId;

    console.log("classroom", classroomId);

    if (req.user.role === "teacher") {
      db.query(
        "SELECT * FROM assignments WHERE classroom_id = ?",
        [classroomId],
        (err, assignmentResult) => {
          if (err) {
            console.error(err);
            return res
              .status(500)
              .json({ error: "Assignment retrieval error" });
          }
          console.log("assignment", assignmentResult);
          db.query(
            "SELECT * FROM assignment_submissions WHERE classroom_id = ? AND assignment_id IN (?)",
            [classroomId, assignmentResult.map((a) => a.assignment_id)],
            (err, submissionResult) => {
              if (err) {
                console.error(err);
                return res
                  .status(500)
                  .json({ error: "Submission retrieval error" });
              }
              console.log("submission", submissionResult);
              res.status(200).json({
                assignments: assignmentResult,
                submissions: submissionResult,
              });
            }
          );
        }
      );
    }
  }
);

// Submit Assignment (Student Only)
app.post(
  "/api/classrooms/:classroomId/assignments/:assignmentId/submit",
  requireAuthentication,
  uploadAssignment.array("assignmentFile"), // Use the upload middleware to handle file uploads
  (req, res) => {
    const classroomId = req.params.classroomId;
    const assignmentId = req.params.assignmentId;
    const userId = req.user.userId; // Get user ID from JWT token
    const submissionTime = new Date();

    console.log("Received request with files:", req.files);
    // if (submissionTime > assignmentDeadline) {
    //   return res.status(400).json({ error: "Assignment submission is late" });
    // }
    const files = req.files;

    // Create a comma-separated string of file names (or paths)
    const fileNames = files ? files.map((file) => file.filename).join(",") : "";

    // Check if a file was successfully uploaded
    if (!req.files) {
      return res.status(400).json({ error: "No file uploaded" });
    }

    const assignmentSubmission = {
      id: generateUniqueId(),
      assignment_id: assignmentId,
      user_id: userId,
      submission_time: submissionTime,
      file_path: fileNames, // Path to the submitted assignment file
    };

    // Save submission record to the database
    db.query(
      "INSERT INTO assignment_submissions SET ?",
      assignmentSubmission,
      (err, results) => {
        if (err) {
          console.error(err);
          return res.status(500).json({ error: "Assignment submission error" });
        }

        res.status(201).json({ message: "Assignment submitted successfully" });
      }
    );
  }
);

//list all assignment for reviews
app.get(
  "/api/classrooms/:classroomId/assignments/submissions",
  requireAuthentication,
  (req, res) => {
    const classroomId = req.params.classroomId;
    const userId = req.user.userId;
    const assignmentId = req.params.assignmentId;
    const userRole = req.user.role;
    console.log("Fetching Test fast: ", classroomId, assignmentId);
    if (userRole === "teacher") {
      // If the user is a teacher, fetch all submissions for the assignment_id
      db.query(
        "SELECT * FROM assignment_submissions WHERE assignment_id IN (SELECT id FROM assignments WHERE classroom_id = ?) ",
        [classroomId],
        (err, results) => {
          if (err) {
            console.error(err);
            return res.status(500).json({ error: "Internal Server Error" });
          }

          // Extract relevant information from results, splitting file paths
          const submissions = results.map((submission) => ({
            id: submission.id,
            assignment_id: submission.assignment_id,
            user_id: submission.user_id,
            submission_time: submission.submission_time,
            // Split file paths into arrays
            file_paths: submission.file_path
              ? submission.file_path.split(",")
              : [],
            score: submission.score,
            status: submission.score !== null ? "Scored" : "Pending",
            // Add any other relevant information you want to include
          }));

          console.log("All submitted assignments:", submissions);
          res.status(200).json(submissions);
        }
      );
    } else if (userRole === "user") {
      // If the user is not a teacher, fetch submissions based on user_id and assignment_id
      db.query(
        "SELECT * FROM assignment_submissions WHERE user_id = ? AND assignment_id = ?",
        [userId, assignmentId],
        (err, results) => {
          if (err) {
            console.error(err);
            return res.status(500).json({ error: "Internal Server Error" });
          }

          // Extract relevant information from results, splitting file paths
          const submissions = results.map((submission) => ({
            submission_id: submission.submission_id,
            submission_time: submission.submission_time,
            // Split file paths into arrays
            file_paths: submission.file_path
              ? submission.file_path.split(",")
              : [],
            // Add any other relevant information you want to include
          }));

          console.log("User's submitted assignments:", submissions);
          res.status(200).json(submissions);
        }
      );
    } else {
      // Handle invalid user role
      res.status(400).json({ error: "Invalid user role" });
    }
  }
);
//getdetais assignment submit
app.get(
  "/api/classrooms/:classroomId/assignments/:assignmentId/submissions",
  requireAuthentication,
  (req, res) => {
    const classroomId = req.params.classroomId;
    const userId = req.user.userId;
    const assignmentId = req.params.assignmentId;
    const userRole = req.user.role;
    console.log("Fetching Test fast USer ", classroomId, assignmentId);

    // If the user is not a teacher, fetch submissions based on user_id and assignment_id
    db.query(
      "SELECT * FROM assignment_submissions WHERE user_id = ? AND assignment_id = ?",
      [userId, assignmentId],
      (err, results) => {
        if (err) {
          console.error(err);
          return res.status(500).json({ error: "Internal Server Error" });
        }

        // Extract relevant information from results, splitting file paths
        const submissions = results.map((submission) => ({
          submission_id: submission.submission_id,
          submission_time: submission.submission_time,
          // Split file paths into arrays
          file_paths: submission.file_path
            ? submission.file_path.split(",")
            : [],
          // Add any other relevant information you want to include
        }));

        console.log("User's submitted assignments:", submissions);
        res.status(200).json(submissions);
      }
    );
  }
);

// Score Assignment (Teacher Only)
app.post(
  "/api/classrooms/:classroomId/assignments/score",
  requireAuthentication,
  (req, res) => {
    // const classroomId = req.params.classroomId;
    // const assignmentId = req.params.assignmentId;
    // const teacherId = req.user.userId; // Get teacher's user ID from JWT token
    const userRole = req.user.role;

    // Ensure that only teachers can access this endpoint
    if (userRole !== "teacher") {
      return res.status(403).json({ error: "Permission denied" });
    }

    const { submissionId, score, feedback } = req.body;
    console.log("Test:", req.body);

    // Update the assignment submission with score and feedback
    db.query(
      "UPDATE assignment_submissions SET score = ?, feedback = ? WHERE id = ? ",
      [score, feedback, submissionId],
      (err, results) => {
        if (err) {
          console.error(err);
          return res.status(500).json({ error: "Scoring assignment error" });
        }

        res.status(200).json({ message: "Assignment scored successfully" });
      }
    );
  }
);

// Get Assignment Scores and Feedback (Student Only)
app.get(
  "/api/classrooms/:classroomId/assignments/:assignmentId",
  requireAuthentication,
  (req, res) => {
    const assignmentId = req.params.assignmentId;
    const userId = req.user.userId;
    // Retrieve scores and feedback for the assignment
    db.query(
      "SELECT score, feedback FROM assignment_submissions WHERE assignment_id = ? AND user_id = ?",
      [assignmentId, userId],
      (err, results) => {
        if (err) {
          console.error(err);
          return res
            .status(500)
            .json({ error: "Error fetching assignment scores and feedback" });
        }
        res.status(200).json({ scoresAndFeedback: results });
      }
    );
  }
);

// Report Suspicious Plagiarism (Teacher Only)
app.post(
  "/api/classrooms/:classroomId/assignments/:assignmentId/report-plagiarism",
  requireAuthentication,
  (req, res) => {
    const classroomId = req.params.classroomId;
    const assignmentId = req.params.assignmentId;
    const teacherId = req.user.userId; // Get teacher's user ID from JWT token
    const userRole = req.user.role;

    // Ensure that only teachers can access this endpoint
    if (userRole !== "teacher") {
      return res.status(403).json({ error: "Permission denied" });
    }

    const { submissionId, reportReason } = req.body;

    // Implement code to report plagiarism cases
    db.query(
      "INSERT INTO plagiarism_reports (teacher_id, classroom_id, assignment_id, submission_id, report_reason) VALUES (?, ?, ?, ?, ?)",
      [teacherId, classroomId, assignmentId, submissionId, reportReason],
      (err, results) => {
        if (err) {
          console.error(err);
          return res.status(500).json({ error: "Error reporting plagiarism" });
        }

        res.status(201).json({ message: "Plagiarism reported successfully" });
      }
    );
  }
);

// API endpoint to create a workspace
app.post("/api/workspaces", requireAuthentication, (req, res) => {
  console.log("handdle body:", req.body);
  const { name, description, classId } = req.body;
  const createdBy = req.user.userId; // Get the user ID from the JWT token
  const id = generateUniqueId(); // You'll need to implement this function

  const workspace = {
    id,
    name,
    class_id: classId,
    description,
    created_by: createdBy,
  };

  const sql = "INSERT INTO workspaces SET ?";
  db.query(sql, workspace, (error, results) => {
    if (error) {
      console.error("Error creating workspace:", error);
      return res.status(500).json({ error: "Internal Server Error" });
    }

    console.log("Workspace created successfully");
    res.status(201).json(results);
  });
});

// Workspace endpoint
app.get("/api/workspaces", requireAuthentication, (req, res) => {
  const { classId } = req.query; // Use req.query to get query parameters

  db.query(
    `SELECT * FROM workspaces WHERE class_id = ? `,
    [classId],
    (err, results) => {
      if (err) {
        console.error(err);
        return res.status(500).json({ error: "Error fetching workspaces" });
      }
      console.log("sending workspace:", results);
      res.status(200).json(results);
    }
  );
});

// Workspace endpoint
app.get("/api/workspaces/details/:id", requireAuthentication, (req, res) => {
  let id = req.params.id;
  db.query(`SELECT * FROM workspaces WHERE id = ? `, [id], (err, results) => {
    if (err) {
      console.error(err);
      return res.status(500).json({ error: "Error fetching workspaces" });
    }
    console.log("sending workspace:", results);
    res.status(200).json(results);
  });
});

app.post("/api/workspaces/invite", requireAuthentication, (req, res) => {
  const { workspaceId, email } = req.body;

  // Validate email
  // You might want to implement a function to check if the email is valid

  // Generate a unique invitation code (you can implement your own logic for this)
  const invitationCode = generateUniqueId();

  // Save the invitation in the database
  const invitation = {
    workspace_id: workspaceId,
    email,
    invitation_code: invitationCode,
  };

  const sql = "INSERT INTO workspace_invitations SET ?";
  db.query(sql, invitation, (error, results) => {
    if (error) {
      console.error("Error inviting user:", error);
      return res.status(500).json({ error: "Internal Server Error" });
    }

    console.log("Invitation sent successfully");
    res.status(201).json(results);
  });
});

app.post("/api/workspaces/add-user", requireAuthentication, (req, res) => {
  const { workspaceId, email } = req.body;

  // Fetch the user ID based on the email
  const getUserSql = "SELECT id FROM users WHERE email = ?";
  db.query(getUserSql, [email], (getUserError, userResults) => {
    if (getUserError) {
      console.error("Error fetching user:", getUserError);
      return res.status(500).json({ error: "Internal Server Error" });
    }

    if (userResults.length === 0) {
      return res.status(404).json({ error: "User not found" });
    }

    const userId = userResults[0].id;

    // Add the user to the workspace members
    const workspaceMember = {
      workspace_id: workspaceId,
      user_id: userId,
    };

    const addMemberSql = "INSERT INTO workspace_members SET ?";
    db.query(
      addMemberSql,
      workspaceMember,
      (addMemberError, addMemberResults) => {
        if (addMemberError) {
          console.error("Error adding user to workspace:", addMemberError);
          return res.status(500).json({ error: "Internal Server Error" });
        }

        console.log("User added to workspace successfully");
        res.status(201).json(addMemberResults);
      }
    );
  });
});

// Set up multer storage and limits
const storage = multer.diskStorage({
  destination: function (req, file, cb) {
    const destinationPath = path.resolve(
      __dirname,
      "uploads",
      "workSpace",
      "posts",
      `${req.user.userId}`
    );
    // Check if the directory exists, and create it if it doesn't
    if (!fs.existsSync(destinationPath)) {
      fs.mkdirSync(destinationPath, { recursive: true });
    }

    cb(null, destinationPath);
  },
  filename: function (req, file, cb) {
    cb(null, Date.now() + "-" + file.originalname); // Specify the file name
  },
});

const upload = multer({ storage: storage });

// Set up multer storage and limits
const storageComment = multer.diskStorage({
  destination: function (req, file, cb) {
    const destinationPath = path.resolve(
      __dirname,
      "uploads",
      "workSpace",
      "posts",
      "comment",
      `${req.user.userId}`
    );
    // Check if the directory exists, and create it if it doesn't
    if (!fs.existsSync(destinationPath)) {
      fs.mkdirSync(destinationPath, { recursive: true });
    }

    cb(null, destinationPath);
  },
  filename: function (req, file, cb) {
    cb(null, Date.now() + "-" + file.originalname); // Specify the file name
  },
});

const uploadComments = multer({ storage: storageComment });

// Endpoint to create a post with file upload support
app.post(
  "/api/workspaces/posts",
  requireAuthentication,
  upload.array("files", 10), // Assuming you have a form field named "file" for file uploads
  (req, res) => {
    const { workspaceId, content } = req.body;

    console.log("create post:", req.body);

    if (!content) {
      return res.status(400).json({ error: "content is required" });
    }

    // Access the uploaded file information
    const files = req.files;

    // Create a comma-separated string of file names (or paths)
    const fileNames = files ? files.map((file) => file.filename).join(",") : "";

    console.log("file", fileNames);

    // Create a new post
    const post = {
      id: generateUniqueId(),
      workspace_id: workspaceId,
      user_id: req.user.userId,
      content: content,
      file: fileNames, // Use the filename if a file is uploaded
    };

    console.log(post);

    const sql = "INSERT INTO workspace_posts SET ?";
    db.query(sql, post, (error, results) => {
      if (error) {
        console.error("Error creating post:", error);
        return res.status(500).json({ error: "Internal Server Error" });
      }

      console.log("Post created successfully");
      res.status(201).json(results);
    });
  }
);

// Update the endpoint for creating comments with file uploads
app.post(
  "/api/workspaces/comments",
  requireAuthentication,
  uploadComments.array("attachmentFiles", 5), // Assuming you allow up to 5 files per comment
  async (req, res) => {
    try {
      const { postId, content } = req.body;

      // Access the uploaded file information
      const files = req.files;

      // Create a new comment
      const comment = {
        id: generateUniqueId(),
        post_id: postId,
        user_id: req.user.userId,
        content,
        files: files ? files.map((file) => file.filename).join(",") : "", // Create a comma-separated string of file names
      };

      console.log("comment:", comment);

      const sql = "INSERT INTO post_comments SET ?";
      db.query(sql, comment, (error, results) => {
        if (error) {
          console.error("Error creating comment:", error);
          return res.status(500).json({ error: "Internal Server Error" });
        }

        console.log("Comment created successfully");
        res.status(201).json(results);
      });
    } catch (error) {
      console.error("Error creating comment:", error);
      res.status(500).json({ error: "Internal Server Error" });
    }
  }
);

app.post(
  "/api/workspaces/upload",
  requireAuthentication,
  upload.single("file"), // Assuming you have a form field named "file" for file uploads
  (req, res) => {
    const { workspaceId, userId, postId } = req.body;
    const filePath = req.file.path;

    // Save file information in the database
    const file = {
      workspace_id: workspaceId,
      user_id: userId,
      post_id: postId,
      file_path: filePath,
    };

    const sql = "INSERT INTO workspace_files SET ?";
    db.query(sql, file, (error, results) => {
      if (error) {
        console.error("Error saving file information:", error);
        return res.status(500).json({ error: "Internal Server Error" });
      }

      console.log("File information saved successfully");
      res.status(201).json(results);
    });
  }
);

// Fetch posts for a workspace
app.get(
  "/api/workspaces/posts/:workspaceId",
  requireAuthentication,
  (req, res) => {
    const { workspaceId } = req.params;
    console.log("workspaceIdr", workspaceId);

    db.query(
      `SELECT * FROM workspace_posts WHERE workspace_id = ?`,
      [workspaceId],
      (err, results) => {
        if (err) {
          console.error(err);
          return res.status(500).json({ error: "Error fetching posts" });
        }

        const postsWithSplitFiles = results.map((post) => {
          const fileArray = post.file
            .split(",")
            .map((fileName) => fileName.trim());

          // Separate files and images, removing images from the files array
          const images = fileArray.filter((fileName) =>
            /\.(png|jpg|jpeg|gif)$/i.test(fileName)
          );
          const files = fileArray.filter(
            (fileName) =>
              !/\.(png|jpg|jpeg|gif)$/i.test(fileName) &&
              !images.includes(fileName)
          );

          return {
            ...post,
            images,
            files,
          };
        });

        console.log("Fetching posts:", postsWithSplitFiles);
        res.status(200).json(postsWithSplitFiles);
      }
    );
  }
);

// Fetch comments for a post
app.get(
  "/api/workspaces/comments/:postId",
  requireAuthentication,
  (req, res) => {
    const { postId } = req.params;

    db.query(
      `SELECT * FROM post_comments WHERE post_id = ?`,
      [postId],
      (err, results) => {
        if (err) {
          console.error(err);
          return res.status(500).json({ error: "Error fetching comments" });
        }

        const postsWithSplitFiles = results.map((post) => {
          const fileArray = post.files
            .split(",")
            .map((fileName) => fileName.trim());

          // Separate files and images, removing images from the files array
          const images = fileArray.filter((fileName) =>
            /\.(png|jpg|jpeg|gif)$/i.test(fileName)
          );
          const files = fileArray.filter(
            (fileName) =>
              !/\.(png|jpg|jpeg|gif)$/i.test(fileName) &&
              !images.includes(fileName)
          );

          return {
            ...post,
            images,
            files,
          };
        });

        console.log("spliting comments:", postsWithSplitFiles);

        console.log("Fetching comments:", results);
        res.status(200).json(postsWithSplitFiles);
      }
    );
  }
);

// Start the Express server
const port = 4049;
app.listen(port, () => {
  console.log(`Server is running on port ${port}`);
});

module.exports = app;
