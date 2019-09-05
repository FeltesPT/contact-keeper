const mongoose = require('mongoose');
// const config = require('config');
// const db = config.get('mongoURI');

const connectDB = () => {
	mongoose
		.connect(process.env.MONGODB_URI, {
			useNewUrlParser: true,
			useCreateIndex: true,
			useFindAndModify: false
		})
		.then(() => console.log('MongoDB Connected'))
		.catch(err => {
			console.error(err.message);
			process.exit(1);
		});
};

module.exports = connectDB;
