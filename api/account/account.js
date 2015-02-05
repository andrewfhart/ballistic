var models  = require('../../models');
var debug = require('debug')('ballistic');
var ACCOUNT = {General:1, Asset: 2, Liability: 3, Investment: 4}
var TRANSACTION = {Spend:1, Income: 2, Purchase: 1, Depreciation: 2, Investment: 1, Interest: 2, Withdrawal: 3}

exports.create = function(req, res) {
  debug(req.body)
  if(!req.body.name || !req.body.type || (req.body.type == ACCOUNT.Investment && !req.body.interest)){
    res.send({success: false, error: 'fields left empty'});
  } else {
    models.Account.create({ name: req.body.name, type: req.body.type, interest: req.body.interest}).then(function(account) {
      account.setUser(req.user);
      debug(account);
      res.send({success: true, account: account});
    });
  }
}

exports.list = function(req, res) {
  debug(req.body)
  if(!req.user){
    res.send({success: false, error: 'must be logged in'});
  } else {
    req.user.getAccounts().then(function(accounts) {
      debug(accounts);
      res.send({success: true, accounts: accounts});
    });
  }
}

exports.get = function(req, res) {
  if(!req.user){
    res.send({success: false, error: 'must be logged in'});
  } else {
    models.Account.find(req.params.id).then(function(account) {
      account.getTransactions({ limit: 5, order: 'date DESC' }).then(function(transactions) {
        switch(account.type){
          case ACCOUNT.Investment:
            generateInvestmentStatistics(account, function(statistics){
              res.send({success: true, account: account, transactions: transactions, statistics: statistics});
            });
          break;
        }
      });
    });
  }
}

exports.statistics = function(req, res) {
  statistics = {
    netWorth: 0, 
    totalInvestments: 0, 
    investmentInterest: 0, 
    yearlyInvestmentIncome: 0,
    goalPercentage: 0,
    estimatedYearlyGrowth: 0
  };
  if(!req.user){
    res.send({success: false, error: 'must be logged in'});
  } else {
    req.user.getAccounts().then(function(accounts) {
      //recurses over accounts and calculates global and account stats
      generateUserStatistics(accounts, statistics, 0, function(accounts, statistics){
        for (var i = 0; i < accounts.length; ++i) {
          if(accounts[i].type == ACCOUNT.Investment){
            accounts[i].statistics.percentOfInvestments = accounts[i].statistics.balance / statistics.totalInvestments * 100;
            statistics.investmentInterest += accounts[i].statistics.percentOfInvestments * accounts[i].interest / 100;
          }
        }
        statistics.investmentGoal = req.usermeta.goal / (statistics.investmentInterest / 100);
        statistics.goalPercentage = statistics.totalInvestments / statistics.investmentGoal * 100;
        statistics.yearlyInvestmentIncome = statistics.totalInvestments * (statistics.investmentInterest / 100);
        statistics.estimatedMonthsRemaining = estimateMonthsRemaining(statistics.totalInvestments, statistics.estimatedYearlyGrowth / 12, statistics.investmentGoal, statistics.investmentInterest / 100, 0);
        statistics.estimatedYearsRemaining = statistics.estimatedMonthsRemaining / 12;
        statistics.goalAge = req.usermeta.age + statistics.estimatedYearsRemaining;
        res.send({success: true, accounts: accounts, statistics: statistics});
      });
    });
  }
}

function generateInvestmentStatistics(account, callback){
  var today = new Date();
  var yearStart = new Date(today.getFullYear(), 0, 0, 0, 0, 0, 0);
  var statistics = {};
  var daysDifferent = dateDiffInDays(yearStart, today);
  if(daysDifferent < 30){
    daysDifferent = 30;
  }

  models.Transaction.sum('amount', { where: { AccountId:  account.id, type: {ne: TRANSACTION.Withdrawal}} }).then(function(totalDeposits) {
    models.Transaction.sum('amount', { where: { AccountId:  account.id, type: TRANSACTION.Withdrawal} }).then(function(totalWithdrawals) {
      models.Transaction.sum('amount', { where: { AccountId:  account.id, type: TRANSACTION.Withdrawal, date: {gt: yearStart} } }).then(function(yearlyWithdrawals) {
        models.Transaction.sum('amount', { where: { AccountId:  account.id, type: TRANSACTION.Investment, date: {gt: yearStart} } }).then(function(yearlyContributions) {
          models.Transaction.sum('amount', { where: { AccountId:  account.id, type: TRANSACTION.Interest, date: {gt: yearStart} } }).then(function(yearlyGrowth) {
            statistics.totalDeposits = totalDeposits || 0;
            statistics.totalWithdrawals = totalWithdrawals || 0;
            statistics.balance = statistics.totalDeposits - statistics.totalWithdrawals;
            statistics.yearlyWithdrawals = yearlyWithdrawals || 0;
            statistics.yearlyContributions = yearlyContributions || 0;
            statistics.yearlyGrowth = yearlyGrowth || 0;
            statistics.estimatedYearlyGrowth = ((statistics.yearlyContributions + statistics.yearlyGrowth - statistics.yearlyWithdrawals) / daysDifferent) * 365;
            callback(statistics);
          });
        });
      });
    });
  });
}

function generateUserStatistics(accounts, statistics, index, callback){
  if (index < accounts.length) {
    accounts[index] = accounts[index].values;
    switch(accounts[index].type){
      case ACCOUNT.Investment:
        generateInvestmentStatistics(accounts[index], function(accountStatistics){
          accounts[index].statistics = accountStatistics;
          statistics.netWorth += accountStatistics.balance;
          statistics.totalInvestments += accountStatistics.balance;
          statistics.estimatedYearlyGrowth += accountStatistics.estimatedYearlyGrowth;
          generateUserStatistics(accounts, statistics, ++index, callback);
        });
      break;
      default:
        generateUserStatistics(accounts, statistics, ++index, callback);
      break;
    }
  } else {
    callback(accounts, statistics);
  }
}

function estimateMonthsRemaining(currentAmount, monthlyContribution, goalAmount, interest, count){
  if(count < 2400){
    if(currentAmount > goalAmount){
      return count;
    } else {
      return estimateMonthsRemaining(currentAmount + monthlyContribution + (monthlyContribution * interest), monthlyContribution, goalAmount, interest, count + 1);
    }
  } else {
    return count;
  }
}

function dateDiffInDays(a, b) {
  // Discard the time and time-zone information.
  var utc1 = Date.UTC(a.getFullYear(), a.getMonth(), a.getDate());
  var utc2 = Date.UTC(b.getFullYear(), b.getMonth(), b.getDate());
  return Math.floor((utc2 - utc1) / 86400000);
}