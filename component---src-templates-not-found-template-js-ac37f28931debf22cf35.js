(window.webpackJsonp=window.webpackJsonp||[]).push([[11],{"/d1K":function(e,t,a){"use strict";a.d(t,"a",(function(){return O}));var n=a("q1tI"),i=a.n(n),l=a("Wbzz"),c=a("iSRb"),o=a.n(c),r=function(e){var t=e.author,a=e.isIndex;return i.a.createElement("div",{className:o.a.author},i.a.createElement(l.Link,{to:"/"},i.a.createElement("img",{src:Object(l.withPrefix)(t.photo),className:o.a.author__photo,width:"75",height:"75",alt:t.name})),!0===a?i.a.createElement("h1",{className:o.a.author__title},i.a.createElement(l.Link,{className:o.a["author__title-link"],to:"/"},t.name)):i.a.createElement("h2",{className:o.a.author__title},i.a.createElement(l.Link,{className:o.a["author__title-link"],to:"/"},t.name)),i.a.createElement("p",{className:o.a.author__subtitle},t.bio))},s=a("7Qib"),m=a("euHg"),u=a.n(m),_=function(e){var t=e.name,a=e.icon;return i.a.createElement("svg",{className:u.a.icon,viewBox:a.viewBox},i.a.createElement("title",null,t),i.a.createElement("path",{d:a.path}))},d=a("aU/I"),h=a.n(d),p=function(e){var t=e.contacts;return i.a.createElement("div",{className:h.a.contacts},i.a.createElement("ul",{className:h.a.contacts__list},Object.keys(t).map((function(e){return t[e]?i.a.createElement("li",{className:h.a["contacts__list-item"],key:e},i.a.createElement("a",{className:h.a["contacts__list-item-link"],href:Object(s.a)(e,t[e]),rel:"noopener noreferrer",target:"_blank"},i.a.createElement(_,{name:e,icon:Object(s.b)(e)}))):null}))))},g=a("Nrk+"),b=a.n(g),E=function(e){var t=e.copyright;return i.a.createElement("div",{className:b.a.copyright},t)},f=a("je8k"),N=a.n(f),v=function(e){var t=e.menu;return i.a.createElement("nav",{className:N.a.menu},i.a.createElement("ul",{className:N.a.menu__list},t.map((function(e){return i.a.createElement("li",{className:N.a["menu__list-item"],key:e.path},i.a.createElement(l.Link,{to:e.path,className:N.a["menu__list-item-link"],activeClassName:N.a["menu__list-item-link--active"]},e.label))}))))},k=a("SySy"),y=a.n(k),x=a("gGy4"),w=a("wiWD"),I=a.n(w),O=function(e){var t=e.isIndex,a=Object(x.b)(),n=a.author,l=a.copyright,c=a.menu;return i.a.createElement("div",{className:y.a.sidebar},i.a.createElement("div",{className:y.a.sidebar__inner},i.a.createElement("div",{className:y.a["logo-image"]},i.a.createElement("img",{src:I.a,className:y.a.headerimage,alt:"logo",onclick:"document.location='/';"})),i.a.createElement(r,{author:n,isIndex:t}),i.a.createElement(v,{menu:c}),i.a.createElement(p,{contacts:n.contacts}),i.a.createElement(E,{copyright:l})))}},"76aL":function(e,t,a){"use strict";a.r(t);var n=a("q1tI"),i=a.n(n),l=a("/d1K"),c=a("Zttt"),o=a("RXmK"),r=a("gGy4");t.default=function(){var e=Object(r.b)(),t=e.title,a=e.subtitle;return i.a.createElement(c.a,{title:"Not Found - "+t,description:a},i.a.createElement(l.a,null),i.a.createElement(o.a,{title:"NOT FOUND"},i.a.createElement("p",null,"You just hit a route that doesn't exist... the sadness.")))}},"Nrk+":function(e,t,a){e.exports={copyright:"Copyright-module--copyright--1ariN"}},RBgx:function(e,t,a){e.exports={page:"Page-module--page--2nMky",page__inner:"Page-module--page__inner--2M_vz",page__title:"Page-module--page__title--GPD8L",page__body:"Page-module--page__body--Ic6i6"}},RXmK:function(e,t,a){"use strict";a.d(t,"a",(function(){return o}));var n=a("q1tI"),i=a.n(n),l=a("RBgx"),c=a.n(l),o=function(e){var t=e.title,a=e.children,l=Object(n.useRef)();return Object(n.useEffect)((function(){l.current.scrollIntoView()})),i.a.createElement("div",{ref:l,className:c.a.page},i.a.createElement("div",{className:c.a.page__inner},t&&i.a.createElement("h1",{className:c.a.page__title},t),i.a.createElement("div",{className:c.a.page__body},a)))}},SySy:function(e,t,a){e.exports={sidebar:"Sidebar-module--sidebar--X4z2p",sidebar__inner:"Sidebar-module--sidebar__inner--Jdc5s",headerimage:"Sidebar-module--headerimage--19Rdy","logo-image":"Sidebar-module--logo-image--XDYae"}},"aU/I":function(e,t,a){e.exports={contacts:"Contacts-module--contacts--1rGd1",contacts__list:"Contacts-module--contacts__list--3OgdW","contacts__list-item":"Contacts-module--contacts__list-item--16p9q","contacts__list-item-link":"Contacts-module--contacts__list-item-link--2MIDn"}},euHg:function(e,t,a){e.exports={icon:"Icon-module--icon--Gpyvw"}},iSRb:function(e,t,a){e.exports={author__photo:"Author-module--author__photo--36xCH",author__title:"Author-module--author__title--2CaTb","author__title-link":"Author-module--author__title-link--Yrism",author__subtitle:"Author-module--author__subtitle--cAaEB"}},je8k:function(e,t,a){e.exports={menu:"Menu-module--menu--Efbin",menu__list:"Menu-module--menu__list--31Zeo","menu__list-item":"Menu-module--menu__list-item--1lJ6B","menu__list-item-link":"Menu-module--menu__list-item-link--10Ush","menu__list-item-link--active":"Menu-module--menu__list-item-link--active--2CbUO"}},wiWD:function(e,t,a){e.exports=a.p+"static/icon2-logo2-c5d80234f0375984456dd06a184cec0c.png"}}]);
//# sourceMappingURL=component---src-templates-not-found-template-js-ac37f28931debf22cf35.js.map