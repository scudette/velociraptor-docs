window.menu = [
    {{ if .IsHome }}
      {{- range .Site.Home.Sections.ByWeight}}
      {{- template "section-tree-nav-json" dict "sect" . -}}
      {{end}}
    {{ end }}
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

{{- define "section-tree-nav-json" }}
 {{- with .sect}}
   {{- if and .IsSection (or (not (or .Params.no_menu .Params.hidden)) )}}
      {{- $numberOfPages := (add (len .Pages) (len .Sections)) -}}
     {"link": "{{.RelPermalink}}", "title": "{{.Params.Pre | html }}{{or .Params.Menutitle .Title | html }}{{safeHTML .Params.Post | html}}", "children": [
        {{- range .Pages }}
          {{- template "section-tree-nav-json" dict "sect" . -}}
        {{- end -}}
      ]},
   {{- else -}}
    {{- if not (or .Params.Hidden .Params.no_menu) -}}
      {"link": "{{.RelPermalink}}", "title": "{{.Params.Pre | html}}{{.LinkTitle | html }}{{.Params.Post | html}}"},
    {{- end -}}
  {{- end -}}
 {{- end -}}
{{- end }}
