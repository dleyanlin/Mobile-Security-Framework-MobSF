var data = [{{ keychaindata | safe}}];
console.log(keychaindata)
$(function () {
$('#table').bootstrapTable({
  data: data
});

});
