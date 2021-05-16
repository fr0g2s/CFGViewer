// bb를 다이어그램으로 표현하기

function getBB(url){
    return new Promise((resolve, reject) => {
        fetch(url, {mode:'no-cors'}).then(res=>{
            resolve(res);
        }, error => {
            console.log(err);
        })
    })
}

var file = $('b#target').attr('value');
var func = $('b#func').attr('value');
var url = "http://localhost:1337/cfgjson?file="+file+'&func='+func;
console.log(url)

getBB(url).then(function(resp){
    console.log(resp);
});