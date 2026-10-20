// Copy-to-clipboard for install snippets. No network access.
document.querySelectorAll('.copy').forEach(function(b){
  b.addEventListener('click',function(){
    var t=b.getAttribute('data-copy'),s=document.getElementById('copy-status');
    var done=function(){b.textContent='Copied';if(s)s.textContent='Copied to clipboard';setTimeout(function(){b.textContent='Copy';if(s)s.textContent=''},1600)};
    if(navigator.clipboard){navigator.clipboard.writeText(t).then(done)}else{var a=document.createElement('textarea');a.value=t;document.body.appendChild(a);a.select();document.execCommand('copy');a.remove();done()}
  });
});
