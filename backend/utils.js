import jwt from 'jsonwebtoken';

/**
 * JWT generter than contain user id, name, email and isAdmin properties.
 * Used when user login.
 * @param {Object} user The Login user object
 * @returns {Object} JWT token that return to users for future.
 */
export const generateToken = (user) => {
  return jwt.sign(
    {
      _id: user._id,
      name: user.name,
      email: user.email,
      isAdmin: user.isAdmin,
    },
    process.env.JWT_SECRET,
    {
      expiresIn: '30d',
    }
  );
};

export const isAuth = (req, res, next) => {
  const authorization = req.headers.authorization;
  if (authorization) {
    const token = authorization.slice(7, authorization.length); // Bearer XXXXXX
    jwt.verify(token, process.env.JWT_SECRET, (err, decode) => {
      if (err) {
        res.status(401).send({ message: 'Invalid Token' });
      } else {
        req.user = decode; // decode contains JWT information
        next();
      }
    });
  } else {
    res.status(401).send({ message: 'No Token' });
  }
};

/**
 * This is a middleware function to validate if the user is admin or not.
 * It have to be called after isAuth function, so that req has user property.
 * @param {*} req request object
 * @param {*} res response object
 * @param {*} next call this if you want to continue.
 */
export const isAdmin = (req, res, next) => {
  if (req.user && req.user.isAdmin) {
    next();
  } else {
    res.status(401).send({ message: 'Invalid Admin Token' });
  }
};
