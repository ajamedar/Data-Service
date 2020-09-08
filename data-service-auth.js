const bcrypt = require("bcryptjs");
const mongoose = require("mongoose");
const Schema = mongoose.Schema;

const userSchema = new Schema({
  userName: {
    type: String,
    unique: true,
  },
  password: String,
  email: String,
  loginHistory: [{ dateTime: Date, userAgent: String }],
});

let User; 

module.exports.initialize = function () {
  return new Promise(function (resolve, reject) {
    let db = mongoose.createConnection(
      "mongodb+srv://admin:admin@cluster0-xxv1b.mongodb.net/test?retryWrites=true&w=majority",
      { useNewUrlParser: true }
    );

    db.once("open", () => {
      User = db.model("users", userSchema);
      resolve();
    });

    db.on("error", (err) => {
      reject(err);
    });
  });
};

module.exports.registerUser = function (userData) {
  return new Promise((resolve, reject) => {
    if (userData.password !== userData.password2)
      return reject("Passwords do not match");
    bcrypt.genSalt(10, function (serr, salt) {
      if (serr) {
        return reject("bcrypt error");
      }
      bcrypt.hash(userData.password, salt, function (hrr, hash) {
        if (hrr) {
          return reject("bcrypt error");
        }
        userData.password = hash;
        userData.password2 = hash;
        new User(userData)
          .save()
          .then(() => {
            resolve();
          })
          .catch((err) => {
            if (err.code === 11000) {
              reject("User Name already taken");
            } else {
              reject("There was an error creating the user: " + err);
            }
          });
      });
    });
  });
};

module.exports.checkUser = function (userData) {
  return new Promise(async (resolve, reject) => {
    User.find({ userName: userData.userName })
      .exec()
      .then((users) => {
        if (!users || users.length < 1) {
          reject("Unable to find user: " + userData.userName);
        } else {
          bcrypt.compare(userData.password, users[0].password).then((res) => {
            if (!res) {
              reject(`Incorrect Password for user: ${userData.userName}`);
            } else {
              users[0].loginHistory.push({
                userAgent: userData.userAgent,
                dateTime: new Date().toString(),
              });
              User.update(
                {
                  userName: users[0].userName,
                },
                { $set: { loginHistory: users[0].loginHistory } },
                { multi: false }
              )
                .exec()
                .then(() => {
                  resolve(users[0]);
                })
                .catch((err) => {
                  reject("There was an error verifying the user: " + err);
                });
            }
          });
        }
      })
      .catch(() => {
        reject("Unable to find user: " + userData.userName);
      });
  });
};
