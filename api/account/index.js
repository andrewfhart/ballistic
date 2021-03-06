'use strict';

var express = require('express');
var controller = require('./account');
var router = express.Router();

router.get('/statistics', controller.statistics);
router.post('/create', controller.create);
router.put('/:id', controller.update);
router.delete('/:id', controller.delete);
router.get('/:id/listtransactions', controller.getTransactions);
router.get('/:id', controller.get);

module.exports = router;