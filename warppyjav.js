var qr = require('qrcode-terminal');

var exec = require('child_process').exec;
var pass = process.argv[2];
var salt = process.argv[3];
var comd = 'python getpkey.py "' + pass + '" "' + salt + '"'

var getPkey = function(pass, salt){
	exec(comd, function(error, stdout, stdin){
		var data = stdout.trim().split('\n')
		data.forEach(function(data){
			console.log(data)
			qr.generate(data);
			(new Array(20)).fill('').forEach(function(){
				console.log('')
			});
		})
	})
}

getPkey(pass, salt);


