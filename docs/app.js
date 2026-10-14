(function(){
  var btn=document.querySelector('.copy'),st=document.getElementById('copy-status');
  if(btn)btn.addEventListener('click',function(){
    var t=btn.getAttribute('data-copy');
    var ok=function(){btn.textContent='Copied';btn.classList.add('done');if(st)st.textContent='Install command copied to clipboard';setTimeout(function(){btn.textContent='Copy';btn.classList.remove('done');},1800);};
    if(navigator.clipboard&&window.isSecureContext){navigator.clipboard.writeText(t).then(ok,fallback);}else fallback();
    function fallback(){var a=document.createElement('textarea');a.value=t;a.setAttribute('readonly','');a.style.position='absolute';a.style.left='-9999px';document.body.appendChild(a);a.select();try{document.execCommand('copy');ok();}catch(e){}document.body.removeChild(a);}
  });
  var body=document.querySelector('.term-body');
  if(!body)return;
  if(window.matchMedia&&window.matchMedia('(prefers-reduced-motion: reduce)').matches)return;
  var typed=body.querySelector('.typed'),out=body.querySelector('.out'),cmd=body.getAttribute('data-cmd');
  var lines=[].slice.call(out.children);
  typed.textContent='';lines.forEach(function(l){l.style.visibility='hidden';});
  var i=0;
  function type(){if(i<=cmd.length){typed.textContent=cmd.slice(0,i++);setTimeout(type,i<3?260:24+Math.random()*38);}else setTimeout(show,420);}
  var j=0;
  function show(){if(j<lines.length){lines[j++].style.visibility='visible';setTimeout(show,95);}}
  setTimeout(type,500);
})();
(function(){
  var q=document.getElementById('tool-q'),n=document.getElementById('tool-n');if(!q)return;
  q.addEventListener('input',function(){var v=q.value.trim().toLowerCase(),c=0;
    [].forEach.call(document.querySelectorAll('.fam'),function(f){var any=0;[].forEach.call(f.querySelectorAll('li'),function(li){var m=!v||li.firstChild.getAttribute('data-q').indexOf(v)>-1;li.hidden=!m;if(m){any++;c++;}});f.hidden=!any;});
    n.textContent=c+(c===1?' tool':' tools');});
})();
