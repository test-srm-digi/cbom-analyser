module.exports = {
  development: {
    username: process.env.DB_USERNAME || 'root',
    password: process.env.DB_PASSWORD || 'asdasd',
    database: process.env.DB_DATABASE || 'dcone-quantum-gaurd',
    host: process.env.DB_HOST || 'localhost',
    dialect: process.env.DB_DIALECT || 'mariadb',
    port: process.env.DB_PORT || 3306,
  },
  test: {
    username: 'root',
    password: 'asdasd',
    database: 'dcone-quantum-gaurd_test',
    host: 'localhost',
    dialect: 'mariadb',
    port: 3306,
  },
  production: {
    username: process.env.DB_USERNAME,
    password: process.env.DB_PASSWORD,
    database: process.env.DB_DATABASE,
    host: process.env.DB_HOST,
    dialect: process.env.DB_DIALECT,
    port: process.env.DB_PORT,
  },
};
