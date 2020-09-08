const Sequelize = require('sequelize');

var sequelize = new Sequelize('df732lv2vdvl7g', 'kuxioiwxgjwlml', '80ebdb208b9b029685240cd037509be791b0252ae63c2baeb659787cb47de08e', {
    host: 'ec2-18-215-99-63.compute-1.amazonaws.com',
    dialect: 'postgres',
    port: 5432,
    dialectOptions: {
        ssl: true
    }
});
var Car = sequelize.define('Car', {
    vin: {
        type: Sequelize.STRING,
        primaryKey: true,
        unique: true
    },
    make: Sequelize.STRING, 
    model: Sequelize.STRING,
    year: Sequelize.STRING
});
var People = sequelize.define('People', {
    first_name: Sequelize.STRING, 
    last_name: Sequelize.STRING,
    phone: Sequelize.STRING,
    address: Sequelize.STRING,
    city: Sequelize.STRING
});

var Store = sequelize.define('Store', {
    retailer: Sequelize.STRING, 
    phone: Sequelize.STRING,
    address: Sequelize.STRING,
    city: Sequelize.STRING   
});

Car.hasMany(People, {foreignKey: 'vin'});



module.exports.initialize = function () {
    return new Promise( (resolve, reject) => {
        sequelize.sync().then( () => {
            resolve();
        }).catch(()=>{
            reject("unable to sync the database");
        });
    });
};



/*****PEOPLE METHODS****/

module.exports.getAllPeople = function(){
    return new Promise((resolve,reject)=>{
        People.findAll().then(function (data) {
            resolve(data);
        }).catch((err) => {
            reject("query returned 0 results");
        });
    });
};

module.exports.getPeopleByVin = function(vin){
    return new Promise((resolve,reject)=>{
        People.findAll({
            where: {
                vin: vin
            }
        }).then(function (data) {
            resolve(data);
        }).catch(() => {
            reject("query returned 0 results");
        });
    });
};

module.exports.getPeopleById = function(id){
    return new Promise(function (resolve, reject) {
        People.findAll({
            where: {
                id: id
            }
        }).then(function (data) {
            resolve(data);
        }).catch(() => {
            reject("query returned 0 results");
        });
    });
};
module.exports.addPeople = function (peopleData) {
    return new Promise(function (resolve, reject) {
        for (var prop in peopleData) {
            if(peopleData[prop] == '')
            peopleData[prop] = null;
        }

        People.create(peopleData).then(() => {
            resolve();
        }).catch((e)=>{
            reject("unable to create person");
        });
    });

};

module.exports.updatePerson = function (personData) {
    return new Promise(function (resolve, reject) {
        for (var prop in personData) {
            if (personData[prop] == '')
            personData[prop] = null;
        }

        People.update(personData, {
            where: { id: personData.id } 
        }).then(() => {
            resolve();
        }).catch((e) => {
            reject("unable to update Person");
        });
    });
};

module.exports.deletePeopleById = function (id) {
    return new Promise(function (resolve, reject) {
        People.destroy({
            where: {
                id: id
            }
        }).then(function () {
            resolve();
        }).catch((err) => {
            reject("unable to delete Person");
        });
    });
};

/*****CARS METHODS****/
module.exports.getCars = function () {
    return new Promise((resolve,reject)=>{
        Car.findAll().then(function (data) {
            resolve(data);
        }).catch((err) => {
            reject("query returned 0 results");
        });
    });
};

module.exports.getCarsByVin = function(vin){
    return new Promise(function (resolve, reject) {
        Car.findAll({
            where: {
                vin: vin
            }
        }).then(function (data) {
            resolve(data);
        }).catch(() => {
            reject("query returned 0 results");
        });
    });
};

module.exports.getCarsByMake = function(make){
    return new Promise(function (resolve, reject) {
        Car.findAll({
            where: {
                make: make
            }
        }).then(function (data) {
            resolve(data);
        }).catch(() => {
            reject("query returned 0 results");
        });
    });
};

module.exports.getCarsByYear = function(year){
    return new Promise(function (resolve, reject) {
        Car.findAll({
            where: {
                year: year
            }
        }).then(function (data) {
            resolve(data);
        }).catch(() => {
            reject("query returned 0 results");
        });
    });
};
module.exports.addCars = function (carData) {
    return new Promise(function (resolve, reject) {
        for (var prop in carData) {
            if(carData[prop] == '')
            carData[prop] = null;
        }

        Car.create(carData).then(() => {
            resolve();
        }).catch((e)=>{
            reject("unable to create car");
        });
    });

};

module.exports.updateCar = function (carData) {
    return new Promise(function (resolve, reject) {
        for (var prop in carData) {
            if (carData[prop] == '')
            carData[prop] = null;
        }

        Car.update(carData, {
            where: { vin: carData.vin } 
        }).then(() => {
            resolve();
        }).catch((e) => {
            reject("unable to update Car");
        });
    });
};

module.exports.deleteCarByVin = function(vin){
    return new Promise(function (resolve, reject) {
        Car.destroy({
            where: {
                vin: vin
            }
        }).then(function () {
            resolve();
        }).catch((err) => {
            reject("unable to delete Car");
        });
    });
};



/*****STORES METHODS****/

module.exports.getStores = function(){
    return new Promise((resolve,reject)=>{
        Store.findAll().then(function (data) {
            resolve(data);
        }).catch((err) => {
            reject("query returned 0 results");
        });
    });
};
module.exports.getStoreById = function(id){
    return new Promise(function (resolve, reject) {
        Store.findAll({
            where: {
                id: id
            }
        }).then(function (data) {
            resolve(data);
        }).catch(() => {
            reject("query returned 0 results");
        });
    });
};
module.exports.getStoresByRetailer = function(retailer){
    return new Promise(function (resolve, reject) {
        Store.findAll({
            where: {
                retailer: retailer
            }
        }).then(function (data) {
            resolve(data);
        }).catch(() => {
            reject("query returned 0 results");
        });
    });
 };
 
module.exports.addStore = function (storeData) {
    return new Promise(function (resolve, reject) {
        for (var prop in storeData) {
            if(storeData[prop] == '')
            storeData[prop] = null;
        }

        Store.create(storeData).then(() => {
            resolve();
        }).catch((e)=>{
            reject("unable to create Store");
        });
    });

};

module.exports.updateStore = function (storeData) {
    return new Promise(function (resolve, reject) {
        for (var prop in storeData) {
            if (storeData[prop] == '')
            storeData[prop] = null;
        }

        Store.update(storeData, {
            where: { id: storeData.id } 
        }).then(() => {
            resolve();
        }).catch((e) => {
            reject("unable to update Store");
        });
    });
};

module.exports.deleteStoreById = function(id){
    return new Promise(function (resolve, reject) {
        Store.destroy({
            where: {
                id: id
            }
        }).then(function () {
            resolve();
        }).catch((err) => {
            reject("unable to delete Store");
        });
    });
};

