// bb를 다이어그램으로 표현하기
async function get_bbjson (){
    var file = $('b#target').attr('value');
    var func = $('b#func').attr('value');
    var url = `http://localhost:1337/cfgjson?file=${file}&func=${func}`;
    if (file != undefined && func != undefined){
        const response = await fetch(url);
        const result = await response.json();
        return result
    }
}
function print_bb(){
    get_bbjson().then((result) => console.log(result));
}

