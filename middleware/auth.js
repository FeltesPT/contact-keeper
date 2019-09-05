const jwt = require('jsonwebtoken');

module.exports = function(req, res, next) {
	// Get Token from header
	const token = req.header('x-auth-token');

	// Check if not token
	if (!token) {
		return res.status(401).json({ msg: 'No token, authorization denied' });
	}

	// There's a token
	try {
		const decoded = jwt.verify(token, process.env.jwtSecret);

		req.user = decoded.user;
		next();
	} catch (err) {
		console.error(err.message);
		res.status(401).json({ msg: 'Token is not valid' });
	}
};
