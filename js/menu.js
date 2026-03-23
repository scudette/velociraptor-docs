window.menu = [
    
    
];

function findlink(children, link) {
  for(let i=0;i<children.length;i++) {
    let child = children[i];
    if(child.link == link) {
      child.active = true;
      return true;
    }

    if(child.children && findlink(child.children, link)) {
      child.expanded = true;
      return true;
    }
  }

  return false;
}
