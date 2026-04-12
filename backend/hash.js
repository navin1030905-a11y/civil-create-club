const bcrypt = require("bcrypt");

bcrypt.hash("sweta123", 10).then(hash => {
  console.log(hash);
});