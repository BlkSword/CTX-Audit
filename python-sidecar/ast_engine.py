import os
import hashlib
import pickle
import logging
import datetime
from typing import Dict, Any, List, Optional
from tree_sitter import Language, Parser
import tree_sitter_languages

# Configure logging
logger = logging.getLogger("deep-audit-ast")

class Symbol:
    def __init__(self, name: str, kind: str, file_path: str, start_line: int, code: str, 
                 parent_classes: List[str] = None, end_line: int = 0, package: str = "", 
                 modifiers: List[str] = None, fields: List[Dict] = None, metadata: Optional[Dict[str, Any]] = None):
        self.name = name
        self.kind = kind  # "class", "function", "method", "method_call", "interface"
        self.file_path = file_path
        self.line = start_line
        self.start_line = start_line
        self.end_line = end_line if end_line else start_line
        self.code = code
        self.parent_classes = parent_classes or []
        self.package = package
        self.modifiers = modifiers or []
        self.fields = fields or []
        self.metadata = metadata or {}
        self.subclasses = [] # Populated post-analysis

    def to_dict(self):
        # Determine language from file extension
        ext = os.path.splitext(self.file_path)[1].lower().replace(".", "")
        if ext == "rs": ext = "rust"
        if ext == "py": ext = "python"
        if ext == "js": ext = "javascript"
        if ext == "ts": ext = "typescript"
        if ext == "tsx": ext = "typescript"
        
        # Generate ID
        node_id = f"{self.file_path}:{self.name}:{self.start_line}"

        node_type = self.kind.capitalize()
        if self.kind == "method_call":
            node_type = "MethodCall"
        elif self.kind == "method":
            node_type = "Method"
        elif self.kind == "function":
            node_type = "Function"
        elif self.kind == "class":
            node_type = "Class"
        elif self.kind == "interface":
            node_type = "Interface"

        meta = {}
        if self.kind in ["class", "interface"]:
            meta["superClasses"] = ", ".join(self.parent_classes)
        meta.update(self.metadata)
        
        return {
            "id": node_id,
            "language": ext,
            "type": node_type,
            "name": self.name,
            "file": self.file_path,
            "package": self.package,
            "startLine": self.start_line,
            "endLine": self.end_line,
            "code": self.code, # Keep for display
            "modifiers": self.modifiers,
            "fields": self.fields,
            "fullClassName": f"{self.package}.{self.name}" if self.package else self.name,
            "metadata": meta,
            # Compatibility fields for existing tools
            "kind": self.kind,
            "line": self.start_line,
            "parent_classes": self.parent_classes,
            "subclasses": self.subclasses
        }

class ASTEngine:
    def __init__(self, cache_dir: str = ".deepaudit_cache"):
        self.base_cache_dir = cache_dir
        self.cache_dir = cache_dir
        self.repository_path: Optional[str] = None
        self.index: Dict[str, Dict[str, Any]] = {}  # file_path -> {mtime, symbols}
        self.class_map: Dict[str, str] = {} # class_name -> file_path
        self.parsers = {}
        self.languages = {}
        self._init_parsers()
        self._load_cache()
        self._rebuild_class_map()

    def use_repository(self, repo_path: str):
        abs_path = os.path.abspath(repo_path)
        key = hashlib.sha1(abs_path.encode("utf-8")).hexdigest()[:16]
        self.repository_path = abs_path
        self.cache_dir = os.path.join(self.base_cache_dir, key)
        self.index = {}
        self.class_map = {}
        self._load_cache()
        self._rebuild_class_map()

    def _rebuild_class_map(self):
        """Rebuild mapping from class names to files for hierarchy analysis."""
        self.class_map = {}
        for file_path, data in self.index.items():
            for sym in data["symbols"]:
                # sym is a Symbol object
                if sym.kind == "class":
                    self.class_map[sym.name] = file_path
                    
    def _init_parsers(self):
        """Initialize tree-sitter parsers for supported languages."""
        supported = {
            ".py": "python",
            ".js": "javascript",
            ".jsx": "javascript",
            ".ts": "typescript",
            ".tsx": "typescript",
            ".rs": "rust",
            ".go": "go",
            ".java": "java",
            ".c": "c",
            ".cpp": "cpp"
        }
        
        for ext, lang_name in supported.items():
            try:
                language = tree_sitter_languages.get_language(lang_name)
                parser = Parser()
                parser.set_language(language)
                self.parsers[ext] = parser
                self.languages[ext] = language
            except Exception as e:
                logger.warning(f"Failed to load parser for {lang_name}: {e}")

    def _load_cache(self):
        """Load AST index from disk."""
        if not os.path.exists(self.cache_dir):
            os.makedirs(self.cache_dir)
        
        cache_file = os.path.join(self.cache_dir, "ast_index.pkl")
        if os.path.exists(cache_file):
            try:
                with open(cache_file, "rb") as f:
                    self.index = pickle.load(f)
                logger.info(f"Loaded AST index with {len(self.index)} files.")
            except Exception as e:
                logger.error(f"Failed to load cache: {e}")
                self.index = {}

    def save_cache(self):
        """Save AST index to disk."""
        if not os.path.exists(self.cache_dir):
            os.makedirs(self.cache_dir)
            
        cache_file = os.path.join(self.cache_dir, "ast_index.pkl")
        try:
            with open(cache_file, "wb") as f:
                pickle.dump(self.index, f)
            logger.info(f"AST索引已保存到: {os.path.abspath(cache_file)}")
        except Exception as e:
            logger.error(f"Failed to save cache: {e}")

    def get_statistics(self) -> Dict[str, Any]:
        """Generate statistics about the AST index."""
        total_nodes = 0
        type_counts = {}
        
        for file_data in self.index.values():
            symbols = file_data["symbols"]
            total_nodes += len(symbols)
            for sym in symbols:
                kind = sym.kind
                # Normalize kind names for better display
                display_kind = kind.capitalize()
                if display_kind == "Function": display_kind = "Method/Function"
                if display_kind == "Class": display_kind = "Class"
                if display_kind == "Interface": display_kind = "Interface"
                
                type_counts[display_kind] = type_counts.get(display_kind, 0) + 1
                
        return {
            "total_nodes": total_nodes,
            "type_counts": type_counts
        }

    def generate_report(self, repository_path: str) -> Dict[str, Any]:
        """Generate a detailed analysis report matching the requested format."""
        nodes = {}
        for file_path, data in self.index.items():
            for sym_obj in data["symbols"]:
                sym_dict = sym_obj.to_dict()
                # Ensure the ID is unique and matches format
                node_id = sym_dict.get("id")
                if not node_id:
                     # Fallback for old cache entries
                     node_id = f"{sym_dict['file']}:{sym_dict['name']}:{sym_dict['startLine']}"
                
                nodes[node_id] = sym_dict

        return {
            "metadata": {
                "build_time": datetime.datetime.now().isoformat(),
                "cache_version": "1.0",
                "node_count": len(nodes),
                "repository_path": repository_path
            },
            "nodes": nodes
        }

    def _extract_java_symbols(self, file_path: str, content: bytes, root_node) -> List[Symbol]:
        symbols = []
        package_name = ""
        
        # 1. Find Package
        query_package = self.languages[".java"].query("(package_declaration (scoped_identifier) @name)")
        captures = query_package.captures(root_node)
        for node, _ in captures:
             package_name = content[node.start_byte:node.end_byte].decode('utf-8')
             break 

        class_stack: List[str] = []
        method_stack: List[str] = []

        def decode(node) -> str:
            return content[node.start_byte:node.end_byte].decode("utf-8", errors="ignore")

        def last_name(text: str) -> str:
            text = text.strip()
            if not text:
                return ""
            for sep in ["->", "::", ".", "?."]:
                text = text.replace(sep, ".")
            parts = [p for p in text.split(".") if p]
            return parts[-1] if parts else text

        def visit(node):
            nonlocal symbols, class_stack, method_stack
            
            if node.type in ["class_declaration", "interface_declaration"]:
                # Name
                name_node = node.child_by_field_name("name")
                if not name_node: return
                name = content[name_node.start_byte:name_node.end_byte].decode('utf-8')
                class_stack.append(name)
                
                # Modifiers
                modifiers = []
                mod_node = node.child_by_field_name("modifiers")
                if mod_node:
                    for child in mod_node.children:
                        modifiers.append(content[child.start_byte:child.end_byte].decode('utf-8'))
                        
                # Superclasses / Interfaces
                parent_classes = []
                super_node = node.child_by_field_name("superclass")
                if super_node:
                     # superclass -> type_identifier
                     parent_classes.append(content[super_node.start_byte:super_node.end_byte].decode('utf-8').replace("extends", "").strip())
                
                interfaces_node = node.child_by_field_name("interfaces")
                if interfaces_node:
                    # interface_type_list -> type_identifier, ...
                    iface_text = content[interfaces_node.start_byte:interfaces_node.end_byte].decode('utf-8').replace("implements", "").strip()
                    for iface in iface_text.split(","):
                        parent_classes.append(iface.strip())

                # Fields
                fields = []
                body_node = node.child_by_field_name("body")
                if body_node:
                    for child in body_node.children:
                        if child.type == "field_declaration":
                            f_modifiers = []
                            f_mod_node = child.child_by_field_name("modifiers")
                            if f_mod_node:
                                for m in f_mod_node.children:
                                    f_modifiers.append(content[m.start_byte:m.end_byte].decode('utf-8'))
                            
                            type_node = child.child_by_field_name("type")
                            f_type = "Unknown"
                            if type_node:
                                f_type = content[type_node.start_byte:type_node.end_byte].decode('utf-8')
                            
                            for gchild in child.children:
                                if gchild.type == "variable_declarator":
                                    f_name_node = gchild.child_by_field_name("name")
                                    f_name = content[f_name_node.start_byte:f_name_node.end_byte].decode('utf-8')
                                    fields.append({
                                        "name": f_name,
                                        "type": f_type,
                                        "startLine": child.start_point[0] + 1,
                                        "endLine": child.end_point[0] + 1,
                                        "modifiers": f_modifiers,
                                        "metadata": {"fullType": f_type}
                                    })
                
                start_line = node.start_point[0] + 1
                end_line = node.end_point[0] + 1
                code = content[node.start_byte:node.end_byte].decode('utf-8')
                if len(code) > 500: code = code[:500] + "..."
                
                kind = "class" if node.type == "class_declaration" else "interface"
                
                symbols.append(Symbol(name, kind, file_path, start_line, code, parent_classes, end_line, package_name, modifiers, fields))

            elif node.type == "method_declaration":
                # Method Definition
                name_node = node.child_by_field_name("name")
                if name_node:
                    name = content[name_node.start_byte:name_node.end_byte].decode('utf-8')
                    start_line = node.start_point[0] + 1
                    end_line = node.end_point[0] + 1
                    method_stack.append(name)
                    code = decode(node)
                    if len(code) > 300: code = code[:300] + "..."
                    metadata = {}
                    if class_stack:
                        metadata["ownerClass"] = class_stack[-1]
                    symbols.append(Symbol(name, "method", file_path, start_line, code, [], end_line, package_name, metadata=metadata))

            elif node.type == "method_invocation":
                # Method Call
                name_node = node.child_by_field_name("name")
                name = ""
                if name_node:
                    name = decode(name_node)
                else:
                    fn_node = node.child_by_field_name("name") or node.child_by_field_name("function")
                    if fn_node:
                        name = decode(fn_node)
                name = last_name(name)
                if name:
                    start_line = node.start_point[0] + 1
                    end_line = node.end_point[0] + 1
                    code = decode(node)
                    if len(code) > 200: code = code[:200] + "..."
                    metadata = {}
                    if class_stack:
                        metadata["callerClass"] = class_stack[-1]
                    if method_stack:
                        metadata["callerMethod"] = method_stack[-1]
                    symbols.append(Symbol(name, "method_call", file_path, start_line, code, [], end_line, package_name, metadata=metadata))
            
            for child in node.children:
                visit(child)

            if node.type in ["class_declaration", "interface_declaration"] and class_stack:
                class_stack.pop()
            if node.type == "method_declaration" and method_stack:
                method_stack.pop()
                
        visit(root_node)
        return symbols

    def _extract_calls_generic(self, file_path: str, content: bytes, ext: str, root_node) -> List[Symbol]:
        symbols: List[Symbol] = []
        class_stack: List[str] = []
        func_stack: List[str] = []

        def decode(node) -> str:
            return content[node.start_byte:node.end_byte].decode("utf-8", errors="ignore")

        def last_name(text: str) -> str:
            text = text.strip()
            if not text:
                return ""
            text = text.replace("?.", ".").replace("::", ".").replace("->", ".")
            parts = [p for p in text.split(".") if p]
            return parts[-1] if parts else text

        if ext in [".py"]:
            class_nodes = {"class_definition"}
            func_nodes = {"function_definition"}
            call_nodes = {"call"}
        elif ext in [".js", ".jsx", ".ts", ".tsx"]:
            class_nodes = {"class_declaration"}
            func_nodes = {"function_declaration", "method_definition"}
            call_nodes = {"call_expression"}
        elif ext in [".rs"]:
            class_nodes = set()
            func_nodes = {"function_item"}
            call_nodes = {"call_expression"}
        elif ext in [".go"]:
            class_nodes = set()
            func_nodes = {"function_declaration", "method_declaration"}
            call_nodes = {"call_expression"}
        else:
            return symbols

        def name_from_node(n) -> str:
            if n is None:
                return ""
            name_node = n.child_by_field_name("name")
            if name_node:
                return decode(name_node).strip()
            for child in n.children:
                if child.type in ["identifier", "type_identifier", "property_identifier", "field_identifier"]:
                    return decode(child).strip()
            return ""

        def visit(n):
            entered_class = False
            entered_func = False

            if n.type in class_nodes:
                nm = name_from_node(n)
                if nm:
                    class_stack.append(nm)
                    entered_class = True

            if n.type in func_nodes:
                nm = name_from_node(n)
                if nm:
                    func_stack.append(nm)
                    entered_func = True

            if n.type in call_nodes:
                fn = n.child_by_field_name("function") or n.child_by_field_name("name")
                callee = last_name(decode(fn)) if fn else ""
                if callee:
                    start_line = n.start_point[0] + 1
                    end_line = n.end_point[0] + 1
                    code = decode(n)
                    if len(code) > 200: code = code[:200] + "..."
                    metadata: Dict[str, Any] = {}
                    if class_stack:
                        metadata["callerClass"] = class_stack[-1]
                    if func_stack:
                        metadata["callerFunction"] = func_stack[-1]
                    symbols.append(Symbol(callee, "method_call", file_path, start_line, code, [], end_line, metadata=metadata))

            for child in n.children:
                visit(child)

            if entered_func and func_stack:
                func_stack.pop()
            if entered_class and class_stack:
                class_stack.pop()

        visit(root_node)
        return symbols

    def _extract_symbols(self, file_path: str, content: bytes, ext: str) -> List[Symbol]:
        """Parse file content and extract symbols based on language."""
        if ext not in self.parsers:
            return []

        parser = self.parsers[ext]
        tree = parser.parse(content)
        root_node = tree.root_node
        
        if ext == ".java":
            return self._extract_java_symbols(file_path, content, root_node)
        
        symbols = []
        queries = {
            ".py": """(class_definition name: (identifier) @name) @class
                      (function_definition name: (identifier) @name) @function""",
            ".rs": """(struct_item name: (type_identifier) @name) @struct
                      (function_item name: (identifier) @name) @function""",
            ".ts": """(class_declaration name: (type_identifier) @name) @class
                      (function_declaration name: (identifier) @name) @function""",
            ".tsx": """(class_declaration name: (type_identifier) @name) @class
                      (function_declaration name: (identifier) @name) @function""",
            ".js": """(class_declaration name: (identifier) @name) @class
                      (function_declaration name: (identifier) @name) @function"""
        }
        
        if ext in queries:
            try:
                query = self.languages[ext].query(queries[ext])
                captures = query.captures(root_node)
                
                for node, tag in captures:
                    if tag in ["class", "function", "struct", "interface"]:
                        name = "unknown"
                        # Try to find identifier
                        for child in node.children:
                            if child.type in ["identifier", "type_identifier"]:
                                name = content[child.start_byte:child.end_byte].decode('utf-8')
                                break
                        
                        start_line = node.start_point[0] + 1
                        end_line = node.end_point[0] + 1
                        code = content[node.start_byte:node.end_byte].decode('utf-8')
                        if len(code) > 200: code = code[:200] + "..."
                        
                        symbols.append(Symbol(name, tag, file_path, start_line, code, [], end_line))
            except Exception as e:
                logger.error(f"Query error in {file_path}: {e}")

        symbols.extend(self._extract_calls_generic(file_path, content, ext, root_node))
                
        return symbols

    def find_call_sites(self, callee_name: str) -> List[Dict[str, Any]]:
        needle = callee_name.strip()
        if not needle:
            return []
        out: List[Dict[str, Any]] = []
        for file_path, data in self.index.items():
            for sym in data.get("symbols", []):
                if sym.get("kind") == "method_call" and sym.get("name") == needle:
                    out.append(sym)
        return out

    def get_call_graph(self, entry: str, max_depth: int = 2) -> Dict[str, Any]:
        entry = entry.strip()
        if not entry:
            return {"entry": entry, "nodes": [], "edges": []}

        edges: List[Dict[str, Any]] = []
        nodes: Dict[str, Dict[str, Any]] = {}

        def add_node(node_id: str, label: str):
            if node_id not in nodes:
                nodes[node_id] = {"id": node_id, "label": label}

        def caller_label(call_sym: Dict[str, Any]) -> str:
            meta = call_sym.get("metadata") or {}
            cls = meta.get("callerClass") or ""
            m = meta.get("callerMethod") or meta.get("callerFunction") or ""
            if cls and m:
                return f"{cls}.{m}"
            if m:
                return str(m)
            return f"{call_sym.get('file')}:{call_sym.get('startLine')}"

        queue: List[str] = [entry]
        visited: set[str] = set()
        depth = 0

        while queue and depth < max_depth:
            next_queue: List[str] = []
            for current in queue:
                if current in visited:
                    continue
                visited.add(current)
                add_node(current, current)

                for file_path, data in self.index.items():
                    for sym in data.get("symbols", []):
                        if sym.get("kind") != "method_call":
                            continue
                        meta = sym.get("metadata") or {}
                        caller = meta.get("callerMethod") or meta.get("callerFunction") or ""
                        callee = sym.get("name") or ""
                        if caller == current:
                            caller_id = current
                            callee_id = callee
                            add_node(callee_id, callee)
                            edges.append({"from": caller_id, "to": callee_id, "file": sym.get("file"), "line": sym.get("startLine")})
                            if callee_id and callee_id not in visited:
                                next_queue.append(callee_id)
            queue = next_queue
            depth += 1

        return {"entry": entry, "nodes": list(nodes.values()), "edges": edges}

    def get_knowledge_graph(self, limit: int = 200) -> Dict[str, Any]:
        """
        Build a knowledge graph of the project (Files, Classes, Functions).
        """
        nodes: Dict[str, Dict[str, Any]] = {}
        edges: List[Dict[str, Any]] = []
        
        count = 0
        
        # 1. Add File Nodes
        for file_path, data in self.index.items():
            if count >= limit: break
            
            rel_path = os.path.basename(file_path)
            if self.repository_path:
                try:
                    rel_path = os.path.relpath(file_path, self.repository_path)
                except:
                    pass
            
            nodes[file_path] = {
                "id": file_path,
                "label": rel_path,
                "type": "file",
                "data": {"path": file_path}
            }
            count += 1
            
            # 2. Add Symbol Nodes and Edges
            for sym in data.get("symbols", []):
                if count >= limit: break
                if sym.get("kind") in ["method_call", "variable"]: continue
                
                sym_id = sym.get("id")
                if not sym_id:
                     sym_id = f"{file_path}:{sym.get('name')}:{sym.get('startLine')}"
                
                label = sym.get("name")
                kind = sym.get("kind")
                
                if sym_id not in nodes:
                    nodes[sym_id] = {
                        "id": sym_id,
                        "label": label,
                        "type": kind,
                        "data": sym
                    }
                    count += 1
                    
                    # Edge: File -> Symbol (DEFINES)
                    edges.append({
                        "id": f"e_{file_path}_{sym_id}",
                        "source": file_path,
                        "target": sym_id,
                        "label": "defines"
                    })
                    
                    # Edge: Class -> SuperClass (INHERITS)
                    if kind == "class":
                        parents = sym.get("parent_classes", [])
                        for p in parents:
                            # Try to resolve parent class
                            if p in self.class_map:
                                parent_file = self.class_map[p]
                                # We don't know the exact ID of parent class without searching, 
                                # but we can try to find it in current nodes or skip
                                # For now, let's just add a node if we can find it
                                pass

        return {"nodes": list(nodes.values()), "edges": edges}

    def update_file(self, file_path: str):
        """Update index for a single file if changed."""
        if not os.path.exists(file_path):
            if file_path in self.index:
                del self.index[file_path]
            return

        ext = os.path.splitext(file_path)[1].lower()
        if ext not in self.parsers:
            return

        try:
            mtime = os.path.getmtime(file_path)
            # Check cache
            if file_path in self.index and self.index[file_path]["mtime"] == mtime:
                return

            # Re-parse
            with open(file_path, "rb") as f:
                content = f.read()
            
            symbols = self._extract_symbols(file_path, content, ext)
            
            self.index[file_path] = {
                "mtime": mtime,
                "symbols": [s.to_dict() for s in symbols]
            }
            
            # Update class map
            for s in symbols:
                if s.kind == "class":
                    self.class_map[s.name] = file_path

        except Exception as e:
            logger.error(f"Error updating file {file_path}: {e}")

    def scan_project(self, root_path: str, ctx=None):
        """Scan entire project and update index."""
        count = 0
        for root, dirs, files in os.walk(root_path):
            # Ignore common garbage
            if "node_modules" in dirs: dirs.remove("node_modules")
            if ".git" in dirs: dirs.remove(".git")
            if "target" in dirs: dirs.remove("target")
            if "__pycache__" in dirs: dirs.remove("__pycache__")
            
            for file in files:
                file_path = os.path.join(root, file)
                self.update_file(file_path)
                count += 1
                if ctx and count % 50 == 0:
                    pass # Optional progress report
                    
        self.save_cache()
        return count

    def search_symbols(self, query: str) -> List[Dict[str, Any]]:
        """Search for symbols matching the query."""
        results = []
        query = query.lower()
        
        for file_path, data in self.index.items():
            for symbol in data["symbols"]:
                if query in symbol.name.lower():
                    results.append(symbol.to_dict())
        
        return results

    def get_file_structure(self, file_path: str) -> List[Dict[str, Any]]:
        """Get all symbols defined in a file."""
        if file_path in self.index:
            return self.index[file_path]["symbols"]
        
        # Try to update if missing
        self.update_file(file_path)
        if file_path in self.index:
            return self.index[file_path]["symbols"]
            
        return []

    def get_class_hierarchy(self, class_name: str) -> Dict[str, Any]:
        """Get the inheritance hierarchy for a class."""
        # Find the class symbol
        target_symbol = None
        target_file = self.class_map.get(class_name)
        
        if not target_file:
            return {"error": f"在索引中未找到类 '{class_name}'。"}
            
        for sym in self.index[target_file]["symbols"]:
            if sym["name"] == class_name and sym["kind"] == "class":
                target_symbol = sym
                break
                
        if not target_symbol:
             return {"error": f"未找到类 '{class_name}' 的符号定义。"}

        # Build Upward Hierarchy (Parents)
        parents = []
        queue = [class_name]
        visited = set()
        
        while queue:
            current_name = queue.pop(0)
            if current_name in visited:
                continue
            visited.add(current_name)
            
            # Find symbol for current_name
            current_file = self.class_map.get(current_name)
            if not current_file:
                continue
                
            current_sym = None
            for sym in self.index[current_file]["symbols"]:
                if sym["name"] == current_name and sym["kind"] == "class":
                    current_sym = sym
                    break
            
            if current_sym:
                if current_name != class_name:
                    parents.append({
                        "name": current_name,
                        "file": current_file,
                        "line": current_sym["line"]
                    })
                
                # Add parents to queue
                if "parent_classes" in current_sym:
                     queue.extend(current_sym["parent_classes"])

        # Build Downward Hierarchy (Children - Simplified Scan)
        # In a real graph DB this is O(1), here it is O(N) scan unless we build reverse index
        children = []
        for file_path, data in self.index.items():
            for sym in data["symbols"]:
                if sym["kind"] == "class" and "parent_classes" in sym:
                    if class_name in sym["parent_classes"]:
                         children.append({
                            "name": sym["name"],
                            "file": file_path,
                            "line": sym["line"]
                        })
        
        return {
            "class": class_name,
            "file": target_file,
            "parents": parents,
            "children": children
        }
