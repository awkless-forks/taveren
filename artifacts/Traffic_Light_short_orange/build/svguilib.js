var sys = function (__mod_name__) {
    if(sys.__was_initialized__) return;
    sys.__was_initialized__ = true;
if (__mod_name__ == null) __mod_name__ = 'sys';
sys.__name__ = __mod_name__;
    sys.platform = String('');
    sys.overrides = new pyjslib.Dict([]);
    sys.loadpath = null;
    sys.stacktrace = null;
    sys.appname = null;
sys.setloadpath = function(lp) {
    sys.loadpath = lp;
    return null;
};
sys.setloadpath.__name__ = 'setloadpath';

sys.setappname = function(an) {
    sys.appname = an;
    return null;
};
sys.setappname.__name__ = 'setappname';

sys.getloadpath = function() {
    return sys.loadpath;
};
sys.getloadpath.__name__ = 'getloadpath';

sys.addoverride = function(module_name, path) {
    overrides.__setitem__(module_name, path);
    return null;
};
sys.addoverride.__name__ = 'addoverride';

sys.addstack = function(linedebug) {

        if (pyjslib.bool((sys.stacktrace === null))) {
            sys.stacktrace = new pyjslib.List([]);
        }
        sys.stacktrace.append(linedebug);
    
};
sys.addstack.__name__ = 'addstack';

sys.popstack = function() {

        sys.stacktrace.pop()
    
};
sys.popstack.__name__ = 'popstack';

sys.printstack = function() {

        var res = '';

        var __l = sys.stacktrace.__iter__();
        try {
            while (true) {
                var l = __l.next();
                res +=  ( l + '\n' ) ;
            }
        } catch (e) {
            if (e != pyjslib.StopIteration) {
                throw e;
            }
        }

        return res;
    
};
sys.printstack.__name__ = 'printstack';

return this;

}; /* end sys */ 

function pyjs_extend(klass, base) {
    function klass_object_inherit() {}
    klass_object_inherit.prototype = base.prototype;
    klass_object = new klass_object_inherit();
    for (var i in base.prototype.__class__) {
        v = base.prototype.__class__[i];
        if (typeof v == "function" && (v.class_method || v.static_method || v.unbound_method))
        {
            klass_object[i] = v;
        }
    }

    function klass_inherit() {}
    klass_inherit.prototype = klass_object;
    klass.prototype = new klass_inherit();
    klass_object.constructor = klass;
    klass.prototype.__class__ = klass_object;

    for (var i in base.prototype) {
        v = base.prototype[i];
        if (typeof v == "function" && v.instance_method)
        {
            klass.prototype[i] = v;
        }
    }
}

/* creates a class, derived from bases, with methods and variables */
function pyjs_type(clsname, bases, methods)
{
    var fn_cls = function() {};
    fn_cls.__name__ = clsname;
    var fn = function() {
        var instance = new fn_cls();
        if(instance.__init__) instance.__init__.apply(instance, arguments);
        return instance;
    }
    fn_cls.__initialize__ = function() {
        if (fn_cls.__was_initialized__) return;
        fn_cls.__was_initialized__ = true;
        fn_cls.__extend_baseclasses();
        fn_cls.prototype.__class__.__new__ = fn;
        fn_cls.prototype.__class__.__name__ = clsname;
    }
    fn_cls.__extend_baseclasses = function() {
        var bi;
        for (bi in fn_cls.__baseclasses)
        {
            var b = fn_cls.__baseclasses[bi];
            if (b.__was_initialized__)
            {
                continue;
            }
            b.__initialize__();
        }
        for (bi in fn_cls.__baseclasses)
        {
            var b = fn_cls.__baseclasses[bi];
            pyjs_extend(fn_cls, b);
        }
    }
    if (!bases) {
        bases = [pyjslib.__Object];
    }
    fn_cls.__baseclasses = bases;

    fn_cls.__initialize__();

    for (k in methods) {
        var mth = methods[k];
        var mtype = typeof mth;
        if (mtype == "function" ) {
            fn_cls.prototype[k] = mth;
            fn_cls.prototype.__class__[k] = function () {
                return fn_cls.prototype[k].call.apply(
                       fn_cls.prototype[k], arguments);
            };
            fn_cls.prototype.__class__[k].unbound_method = true;
            fn_cls.prototype.instance_method = true;
            fn_cls.prototype.__class__[k].__name__ = k;
            fn_cls.prototype[k].__name__ = k;
        } else {
            fn_cls.prototype.__class__[k] = mth;
        }
    }
    return fn;
}
function pyjs_kwargs_call(obj, func, star_args, args)
{
    var call_args;

    if (star_args)
    {
        if (!pyjslib.isIteratable(star_args))
        {
            throw (pyjslib.TypeError(func.__name__ + "() arguments after * must be a sequence" + pyjslib.repr(star_args)));
        }
        call_args = Array();
        var __i = star_args.__iter__();
        var i = 0;
        try {
            while (true) {
                call_args[i]=__i.next();
                i++;
            }
        } catch (e) {
            if (e != pyjslib.StopIteration) {
                throw e;
            }
        }

        if (args)
        {
            var n = star_args.length;
            for (var i=0; i < args.length; i++) {
                call_args[n+i]=args[i];
            }
        }
    }
    else
    {
        call_args = args;
    }
    return func.apply(obj, call_args);
}

function pyjs_kwargs_function_call(func, star_args, args)
{
    return pyjs_kwargs_call(null, func, star_args, args);
}

function pyjs_kwargs_method_call(obj, method_name, star_args, args)
{
    var method = obj[method_name];
    if (method.parse_kwargs)
    {
        args = method.parse_kwargs.apply(null, args);
    }
    return pyjs_kwargs_call(obj, method, star_args, args);
}

//String.prototype.__getitem__ = String.prototype.charAt;
//String.prototype.upper = String.prototype.toUpperCase;
//String.prototype.lower = String.prototype.toLowerCase;
//String.prototype.find=pyjslib.String_find;
//String.prototype.join=pyjslib.String_join;
//String.prototype.isdigit=pyjslib.String_isdigit;
//String.prototype.__iter__=pyjslib.String___iter__;
//
//String.prototype.__replace=String.prototype.replace;
//String.prototype.replace=pyjslib.String_replace;
//
//String.prototype.split=pyjslib.String_split;
//String.prototype.strip=pyjslib.String_strip;
//String.prototype.lstrip=pyjslib.String_lstrip;
//String.prototype.rstrip=pyjslib.String_rstrip;
//String.prototype.startswith=pyjslib.String_startswith;

var str = String;

var pyjslib = function (__mod_name__) {
    if(pyjslib.__was_initialized__) return;
    pyjslib.__was_initialized__ = true;
if (__mod_name__ == null) __mod_name__ = 'pyjslib';
pyjslib.__name__ = __mod_name__;
pyjslib.import_module = function(path, parent_module, module_name, dynamic, async) {
    if (typeof dynamic == 'undefined') dynamic=1;
    if (typeof async == 'undefined') async=false;

        var cache_file;

        if (module_name == "sys" || module_name == 'pyjslib')
        {
            /*module_load_request[module_name] = 1;*/
            return;
        }

        if (path == null)
        {
            path = './';
        }

        var override_name = sys.platform + "." + module_name;
        if (((sys.overrides != null) &&
             (sys.overrides.has_key(override_name))))
        {
            cache_file =  sys.overrides.__getitem__(override_name) ;
        }
        else
        {
            cache_file =  module_name ;
        }

        cache_file = (path + cache_file + '.cache.js' ) ;

        //alert("cache " + cache_file + " " + module_name + " " + parent_module);

        /* already loaded? */
        if (module_load_request[module_name])
        {
            if (module_load_request[module_name] >= 3 && parent_module != null)
            {
                //onload_fn = parent_module + '.' + module_name + ' = ' + module_name + ';';
                //pyjs_eval(onload_fn); /* set up the parent-module namespace */
            }
            return;
        }
        if (typeof (module_load_request[module_name]) == 'undefined')
        {
            module_load_request[module_name] = 1;
        }

        /* following a load, this first executes the script
         * "preparation" function MODULENAME_loaded_fn()
         * and then sets up the loaded module in the namespace
         * of the parent.
         */

        onload_fn = ''; // module_name + "_loaded_fn();"

        if (parent_module != null)
        {
            //onload_fn += parent_module + '.' + module_name + ' = ' + module_name + ';';
            /*pmod = parent_module + '.' + module_name;
            onload_fn += 'alert("' + pmod + '"+' + pmod+');';*/
        }


        if (dynamic)
        {
            /* this one tacks the script onto the end of the DOM
             */

            pyjs_load_script(cache_file, onload_fn, async);

            /* this one actually RUNS the script (eval) into the page.
               my feeling is that this would be better for non-async
               but i can't get it to work entirely yet.
             */
            /*pyjs_ajax_eval(cache_file, onload_fn, async);*/
        }
        else
        {
            if (module_name != "pyjslib" &&
                module_name != "sys")
                pyjs_eval(onload_fn);
        }

    
};
pyjslib.import_module.__name__ = 'import_module';

pyjslib.import_module.parse_kwargs = function ( __kwargs, path, parent_module, module_name, dynamic, async ) {
    if (typeof dynamic == 'undefined')
        dynamic=__kwargs.dynamic;
    if (typeof async == 'undefined')
        async=__kwargs.async;
    var __r = [path, parent_module, module_name, dynamic, async];
    return __r;
};

function import_wait(proceed_fn, parent_mod, dynamic) {

    var data = '';
    var element = $doc.createElement("div");
    $doc.body.appendChild(element);
    function write_dom(txt) {
        element.innerHTML = txt + '<br />';
    }

    var timeoutperiod = 1;
    if (dynamic)
        var timeoutperiod = 1;

    var wait = function() {

        var status = '';
        for (l in module_load_request)
        {
            var m = module_load_request[l];
            if (l == "sys" || l == 'pyjslib')
                continue;
            status += l + m + " ";
        }

        //write_dom( " import wait " + wait_count + " " + status + " parent_mod " + parent_mod);
        wait_count += 1;

        if (status == '')
        {
            setTimeout(wait, timeoutperiod);
            return;
        }

        for (l in module_load_request)
        {
            var m = module_load_request[l];
            if (l == "sys" || l == 'pyjslib')
            {
                module_load_request[l] = 4;
                continue;
            }
            if ((parent_mod != null) && (l == parent_mod))
            {
                if (m == 1)
                {
                    setTimeout(wait, timeoutperiod);
                    return;
                }
                if (m == 2)
                {
                    /* cheat and move app on to next stage */
                    module_load_request[l] = 3;
                }
            }
            if (m == 1 || m == 2)
            {
                setTimeout(wait, timeoutperiod);
                return;
            }
            if (m == 3)
            {
                //alert("waited for module " + l + ": loaded");
                module_load_request[l] = 4;
                mod_fn = modules[l];
            }
        }
        //alert("module wait done");

        if (proceed_fn.importDone)
            proceed_fn.importDone(proceed_fn);
        else
            proceed_fn();
    }

    wait();
}

pyjslib.__Object = function () {
}
pyjslib.Object = function() {
    var instance = new pyjslib.__Object();
    if(instance.__init__) instance.__init__.apply(instance, arguments);
    return instance;
};
pyjslib.Object.__name__ = 'Object';

pyjslib.__Object.__initialize__ = function () {
    if(pyjslib.__Object.__was_initialized__) return;
    pyjslib.__Object.__was_initialized__ = true;
    pyjs_extend(pyjslib.__Object, pyjslib.__Object);
    pyjslib.__Object.prototype.__class__.__new__ = pyjslib.Object;
    pyjslib.__Object.prototype.__class__.__name__ = 'Object';
    pyjslib.__Object.prototype.__init__ = function() {
    };
    pyjslib.__Object.prototype.__class__.__init__ = function() {
        return pyjslib.__Object.prototype.__init__.call.apply(pyjslib.__Object.prototype.__init__, arguments);
    };
    pyjslib.__Object.prototype.__class__.__init__.unbound_method = true;
    pyjslib.__Object.prototype.__init__.instance_method = true;
    pyjslib.__Object.prototype.__class__.__init__.__name__ = '__init__';
pyjslib.__Object.prototype.__init__.__name__ = '__init__';
}
pyjslib.__Object.__initialize__();
    pyjslib.object = pyjslib.__Object.prototype.__class__;
pyjslib.__Modload = function () {
}
pyjslib.Modload = function(path, app_modlist, app_imported_fn, dynamic, parent_mod) {
    var instance = new pyjslib.__Modload();
    if(instance.__init__) instance.__init__.apply(instance, arguments);
    return instance;
};
pyjslib.Modload.__name__ = 'Modload';

pyjslib.__Modload.__initialize__ = function () {
    if(pyjslib.__Modload.__was_initialized__) return;
    pyjslib.__Modload.__was_initialized__ = true;
    pyjs_extend(pyjslib.__Modload, pyjslib.__Object);
    pyjslib.__Modload.prototype.__class__.__new__ = pyjslib.Modload;
    pyjslib.__Modload.prototype.__class__.__name__ = 'Modload';
    pyjslib.__Modload.prototype.__init__ = function(path, app_modlist, app_imported_fn, dynamic, parent_mod) {
    this.app_modlist = app_modlist;
    this.app_imported_fn = app_imported_fn;
    this.path = path;
    this.idx = 0;
    this.dynamic = dynamic;
    this.parent_mod = parent_mod;
    };
    pyjslib.__Modload.prototype.__class__.__init__ = function() {
        return pyjslib.__Modload.prototype.__init__.call.apply(pyjslib.__Modload.prototype.__init__, arguments);
    };
    pyjslib.__Modload.prototype.__class__.__init__.unbound_method = true;
    pyjslib.__Modload.prototype.__init__.instance_method = true;
    pyjslib.__Modload.prototype.__class__.__init__.__name__ = '__init__';
pyjslib.__Modload.prototype.__init__.__name__ = '__init__';
    pyjslib.__Modload.prototype.next = function() {

        var __i = pyjslib.range(pyjslib.len(this.app_modlist.__getitem__(this.idx))).__iter__();
        try {
            while (true) {
                var i = __i.next();
                
        
    var app = this.app_modlist.__getitem__(this.idx).__getitem__(i);
    pyjslib.import_module(this.path, this.parent_mod, app, this.dynamic, true);

            }
        } catch (e) {
            if (e.__name__ != pyjslib.StopIteration.__name__) {
                throw e;
            }
        }
        
    this.idx += 1;
    if (pyjslib.bool((this.idx >= pyjslib.len(this.app_modlist)))) {
    import_wait(this.app_imported_fn, this.parent_mod, this.dynamic);
    }
    else {
    import_wait(pyjslib.getattr(this, String('next')), this.parent_mod, this.dynamic);
    }
    };
    pyjslib.__Modload.prototype.__class__.next = function() {
        return pyjslib.__Modload.prototype.next.call.apply(pyjslib.__Modload.prototype.next, arguments);
    };
    pyjslib.__Modload.prototype.__class__.next.unbound_method = true;
    pyjslib.__Modload.prototype.next.instance_method = true;
    pyjslib.__Modload.prototype.__class__.next.__name__ = 'next';
pyjslib.__Modload.prototype.next.__name__ = 'next';
}
pyjslib.__Modload.__initialize__();
pyjslib.get_module = function(module_name) {
    var _ev = sprintf(String('__mod = %s\x3B'), module_name);
pyjs_eval(_ev);
    return __mod;
};
pyjslib.get_module.__name__ = 'get_module';

pyjslib.preload_app_modules = function(path, app_modnames, app_imported_fn, dynamic, parent_mod) {
    if (typeof parent_mod == 'undefined') parent_mod=null;
    var loader = pyjslib.Modload(path, app_modnames, app_imported_fn, dynamic, parent_mod);
    loader.next();
    return null;
};
pyjslib.preload_app_modules.__name__ = 'preload_app_modules';

pyjslib.preload_app_modules.parse_kwargs = function ( __kwargs, path, app_modnames, app_imported_fn, dynamic, parent_mod ) {
    if (typeof parent_mod == 'undefined')
        parent_mod=__kwargs.parent_mod;
    var __r = [path, app_modnames, app_imported_fn, dynamic, parent_mod];
    return __r;
};

    pyjslib.import_module(sys.loadpath, 'pyjslib', 'sys', 0, false);
    
pyjslib.__BaseException = function () {
}
pyjslib.BaseException = function() {
    var args = new pyjslib.Tuple();
    for(var __va_arg=0; __va_arg < arguments.length; __va_arg++) {
        var __arg = arguments[__va_arg];
        args.append(__arg);
    }
    var instance = new pyjslib.__BaseException();
    if(instance.__init__) instance.__init__.apply(instance, arguments);
    return instance;
};
pyjslib.BaseException.__name__ = 'BaseException';

pyjslib.__BaseException.__initialize__ = function () {
    if(pyjslib.__BaseException.__was_initialized__) return;
    pyjslib.__BaseException.__was_initialized__ = true;
    pyjs_extend(pyjslib.__BaseException, pyjslib.__Object);
    pyjslib.__BaseException.prototype.__class__.__new__ = pyjslib.BaseException;
    pyjslib.__BaseException.prototype.__class__.__name__ = 'BaseException';
    pyjslib.__BaseException.prototype.__class__.name = String('BaseException');
    pyjslib.__BaseException.prototype.__init__ = function() {
    var args = new pyjslib.Tuple();
    for(var __va_arg=0; __va_arg < arguments.length; __va_arg++) {
        var __arg = arguments[__va_arg];
        args.append(__arg);
    }
    this.args = args;
    };
    pyjslib.__BaseException.prototype.__class__.__init__ = function() {
        return pyjslib.__BaseException.prototype.__init__.call.apply(pyjslib.__BaseException.prototype.__init__, arguments);
    };
    pyjslib.__BaseException.prototype.__class__.__init__.unbound_method = true;
    pyjslib.__BaseException.prototype.__init__.instance_method = true;
    pyjslib.__BaseException.prototype.__class__.__init__.__name__ = '__init__';
pyjslib.__BaseException.prototype.__init__.__name__ = '__init__';
    pyjslib.__BaseException.prototype.__str__ = function() {
    if (pyjslib.bool((pyjslib.len(this.args) === 0))) {
    return String('');
    }
    else if (pyjslib.bool((pyjslib.len(this.args) === 1))) {
    return pyjslib.repr(this.args.__getitem__(0));
    }
    return pyjslib.repr(this.args);
    };
    pyjslib.__BaseException.prototype.__class__.__str__ = function() {
        return pyjslib.__BaseException.prototype.__str__.call.apply(pyjslib.__BaseException.prototype.__str__, arguments);
    };
    pyjslib.__BaseException.prototype.__class__.__str__.unbound_method = true;
    pyjslib.__BaseException.prototype.__str__.instance_method = true;
    pyjslib.__BaseException.prototype.__class__.__str__.__name__ = '__str__';
pyjslib.__BaseException.prototype.__str__.__name__ = '__str__';
    pyjslib.__BaseException.prototype.toString = function() {
    return pyjslib.str(this);
    };
    pyjslib.__BaseException.prototype.__class__.toString = function() {
        return pyjslib.__BaseException.prototype.toString.call.apply(pyjslib.__BaseException.prototype.toString, arguments);
    };
    pyjslib.__BaseException.prototype.__class__.toString.unbound_method = true;
    pyjslib.__BaseException.prototype.toString.instance_method = true;
    pyjslib.__BaseException.prototype.__class__.toString.__name__ = 'toString';
pyjslib.__BaseException.prototype.toString.__name__ = 'toString';
}
pyjslib.__BaseException.__initialize__();
pyjslib.__Exception = function () {
}
pyjslib.Exception = function() {
    var instance = new pyjslib.__Exception();
    if(instance.__init__) instance.__init__.apply(instance, arguments);
    return instance;
};
pyjslib.Exception.__name__ = 'Exception';

pyjslib.__Exception.__initialize__ = function () {
    if(pyjslib.__Exception.__was_initialized__) return;
    pyjslib.__Exception.__was_initialized__ = true;
    if(!pyjslib.__BaseException.__was_initialized__)
        pyjslib.__BaseException.__initialize__();
    pyjs_extend(pyjslib.__Exception, pyjslib.__BaseException);
    pyjslib.__Exception.prototype.__class__.__new__ = pyjslib.Exception;
    pyjslib.__Exception.prototype.__class__.__name__ = 'Exception';
    pyjslib.__Exception.prototype.__class__.name = String('Exception');
}
pyjslib.__Exception.__initialize__();
pyjslib.__TypeError = function () {
}
pyjslib.TypeError = function() {
    var instance = new pyjslib.__TypeError();
    if(instance.__init__) instance.__init__.apply(instance, arguments);
    return instance;
};
pyjslib.TypeError.__name__ = 'TypeError';

pyjslib.__TypeError.__initialize__ = function () {
    if(pyjslib.__TypeError.__was_initialized__) return;
    pyjslib.__TypeError.__was_initialized__ = true;
    if(!pyjslib.__BaseException.__was_initialized__)
        pyjslib.__BaseException.__initialize__();
    pyjs_extend(pyjslib.__TypeError, pyjslib.__BaseException);
    pyjslib.__TypeError.prototype.__class__.__new__ = pyjslib.TypeError;
    pyjslib.__TypeError.prototype.__class__.__name__ = 'TypeError';
    pyjslib.__TypeError.prototype.__class__.name = String('TypeError');
}
pyjslib.__TypeError.__initialize__();
pyjslib.__StandardError = function () {
}
pyjslib.StandardError = function() {
    var instance = new pyjslib.__StandardError();
    if(instance.__init__) instance.__init__.apply(instance, arguments);
    return instance;
};
pyjslib.StandardError.__name__ = 'StandardError';

pyjslib.__StandardError.__initialize__ = function () {
    if(pyjslib.__StandardError.__was_initialized__) return;
    pyjslib.__StandardError.__was_initialized__ = true;
    if(!pyjslib.__Exception.__was_initialized__)
        pyjslib.__Exception.__initialize__();
    pyjs_extend(pyjslib.__StandardError, pyjslib.__Exception);
    pyjslib.__StandardError.prototype.__class__.__new__ = pyjslib.StandardError;
    pyjslib.__StandardError.prototype.__class__.__name__ = 'StandardError';
    pyjslib.__StandardError.prototype.__class__.name = String('StandardError');
}
pyjslib.__StandardError.__initialize__();
pyjslib.__LookupError = function () {
}
pyjslib.LookupError = function() {
    var instance = new pyjslib.__LookupError();
    if(instance.__init__) instance.__init__.apply(instance, arguments);
    return instance;
};
pyjslib.LookupError.__name__ = 'LookupError';

pyjslib.__LookupError.__initialize__ = function () {
    if(pyjslib.__LookupError.__was_initialized__) return;
    pyjslib.__LookupError.__was_initialized__ = true;
    if(!pyjslib.__StandardError.__was_initialized__)
        pyjslib.__StandardError.__initialize__();
    pyjs_extend(pyjslib.__LookupError, pyjslib.__StandardError);
    pyjslib.__LookupError.prototype.__class__.__new__ = pyjslib.LookupError;
    pyjslib.__LookupError.prototype.__class__.__name__ = 'LookupError';
    pyjslib.__LookupError.prototype.__class__.name = String('LookupError');
    pyjslib.__LookupError.prototype.toString = function() {
    return  (  ( this.name + String(': ') )  + this.args.__getitem__(0) ) ;
    };
    pyjslib.__LookupError.prototype.__class__.toString = function() {
        return pyjslib.__LookupError.prototype.toString.call.apply(pyjslib.__LookupError.prototype.toString, arguments);
    };
    pyjslib.__LookupError.prototype.__class__.toString.unbound_method = true;
    pyjslib.__LookupError.prototype.toString.instance_method = true;
    pyjslib.__LookupError.prototype.__class__.toString.__name__ = 'toString';
pyjslib.__LookupError.prototype.toString.__name__ = 'toString';
}
pyjslib.__LookupError.__initialize__();
pyjslib.__KeyError = function () {
}
pyjslib.KeyError = function() {
    var instance = new pyjslib.__KeyError();
    if(instance.__init__) instance.__init__.apply(instance, arguments);
    return instance;
};
pyjslib.KeyError.__name__ = 'KeyError';

pyjslib.__KeyError.__initialize__ = function () {
    if(pyjslib.__KeyError.__was_initialized__) return;
    pyjslib.__KeyError.__was_initialized__ = true;
    if(!pyjslib.__LookupError.__was_initialized__)
        pyjslib.__LookupError.__initialize__();
    pyjs_extend(pyjslib.__KeyError, pyjslib.__LookupError);
    pyjslib.__KeyError.prototype.__class__.__new__ = pyjslib.KeyError;
    pyjslib.__KeyError.prototype.__class__.__name__ = 'KeyError';
    pyjslib.__KeyError.prototype.__class__.name = String('KeyError');
}
pyjslib.__KeyError.__initialize__();
pyjslib.__AttributeError = function () {
}
pyjslib.AttributeError = function() {
    var instance = new pyjslib.__AttributeError();
    if(instance.__init__) instance.__init__.apply(instance, arguments);
    return instance;
};
pyjslib.AttributeError.__name__ = 'AttributeError';

pyjslib.__AttributeError.__initialize__ = function () {
    if(pyjslib.__AttributeError.__was_initialized__) return;
    pyjslib.__AttributeError.__was_initialized__ = true;
    if(!pyjslib.__StandardError.__was_initialized__)
        pyjslib.__StandardError.__initialize__();
    pyjs_extend(pyjslib.__AttributeError, pyjslib.__StandardError);
    pyjslib.__AttributeError.prototype.__class__.__new__ = pyjslib.AttributeError;
    pyjslib.__AttributeError.prototype.__class__.__name__ = 'AttributeError';
    pyjslib.__AttributeError.prototype.__class__.name = String('AttributeError');
    pyjslib.__AttributeError.prototype.toString = function() {
    return sprintf(String('AttributeError: %s of %s'), new pyjslib.Tuple([this.args.__getitem__(1), this.args.__getitem__(0)]));
    };
    pyjslib.__AttributeError.prototype.__class__.toString = function() {
        return pyjslib.__AttributeError.prototype.toString.call.apply(pyjslib.__AttributeError.prototype.toString, arguments);
    };
    pyjslib.__AttributeError.prototype.__class__.toString.unbound_method = true;
    pyjslib.__AttributeError.prototype.toString.instance_method = true;
    pyjslib.__AttributeError.prototype.__class__.toString.__name__ = 'toString';
pyjslib.__AttributeError.prototype.toString.__name__ = 'toString';
}
pyjslib.__AttributeError.__initialize__();

pyjslib.StopIteration = function () { };
pyjslib.StopIteration.prototype = new Error();
pyjslib.StopIteration.name = 'StopIteration';
pyjslib.StopIteration.message = 'StopIteration';

pyjslib.String_find = function(sub, start, end) {
    var pos=this.indexOf(sub, start);
    if (pyjslib.isUndefined(end)) return pos;

    if (pos + sub.length>end) return -1;
    return pos;
}

pyjslib.String_join = function(data) {
    var text="";

    if (pyjslib.isArray(data)) {
        return data.join(this);
    }
    else if (pyjslib.isIteratable(data)) {
        var iter=data.__iter__();
        try {
            text+=iter.next();
            while (true) {
                var item=iter.next();
                text+=this + item;
            }
        }
        catch (e) {
            if (e != pyjslib.StopIteration) throw e;
        }
    }

    return text;
}

pyjslib.String_isdigit = function() {
    return (this.match(/^\d+$/g) != null);
}

pyjslib.String_replace = function(old, replace, count) {
    var do_max=false;
    var start=0;
    var new_str="";
    var pos=0;

    if (!pyjslib.isString(old)) return this.__replace(old, replace);
    if (!pyjslib.isUndefined(count)) do_max=true;

    while (start<this.length) {
        if (do_max && !count--) break;

        pos=this.indexOf(old, start);
        if (pos<0) break;

        new_str+=this.substring(start, pos) + replace;
        start=pos+old.length;
    }
    if (start<this.length) new_str+=this.substring(start);

    return new_str;
}

pyjslib.String_split = function(sep, maxsplit) {
    var items=new pyjslib.List();
    var do_max=false;
    var subject=this;
    var start=0;
    var pos=0;

    if (pyjslib.isUndefined(sep) || pyjslib.isNull(sep)) {
        sep=" ";
        subject=subject.strip();
        subject=subject.replace(/\s+/g, sep);
    }
    else if (!pyjslib.isUndefined(maxsplit)) do_max=true;

    if (subject.length == 0) {
        return items;
    }

    while (start<subject.length) {
        if (do_max && !maxsplit--) break;

        pos=subject.indexOf(sep, start);
        if (pos<0) break;

        items.append(subject.substring(start, pos));
        start=pos+sep.length;
    }
    if (start<=subject.length) items.append(subject.substring(start));

    return items;
}

pyjslib.String___iter__ = function() {
    var i = 0;
    var s = this;
    return {
        'next': function() {
            if (i >= s.length) {
                throw pyjslib.StopIteration;
            }
            return s.substring(i++, i, 1);
        },
        '__iter__': function() {
            return this;
        }
    };
}

pyjslib.String_strip = function(chars) {
    return this.lstrip(chars).rstrip(chars);
}

pyjslib.String_lstrip = function(chars) {
    if (pyjslib.isUndefined(chars)) return this.replace(/^\s+/, "");

    return this.replace(new RegExp("^[" + chars + "]+"), "");
}

pyjslib.String_rstrip = function(chars) {
    if (pyjslib.isUndefined(chars)) return this.replace(/\s+$/, "");

    return this.replace(new RegExp("[" + chars + "]+$"), "");
}

pyjslib.String_startswith = function(prefix, start) {
    if (pyjslib.isUndefined(start)) start = 0;

    if (this.substring(start, prefix.length) == prefix) return true;
    return false;
}

pyjslib.abs = Math.abs;


pyjslib.__Class = function () {
}
pyjslib.Class = function(name) {
    var instance = new pyjslib.__Class();
    if(instance.__init__) instance.__init__.apply(instance, arguments);
    return instance;
};
pyjslib.Class.__name__ = 'Class';

pyjslib.__Class.__initialize__ = function () {
    if(pyjslib.__Class.__was_initialized__) return;
    pyjslib.__Class.__was_initialized__ = true;
    pyjs_extend(pyjslib.__Class, pyjslib.__Object);
    pyjslib.__Class.prototype.__class__.__new__ = pyjslib.Class;
    pyjslib.__Class.prototype.__class__.__name__ = 'Class';
    pyjslib.__Class.prototype.__init__ = function(name) {
    this.name = name;
    };
    pyjslib.__Class.prototype.__class__.__init__ = function() {
        return pyjslib.__Class.prototype.__init__.call.apply(pyjslib.__Class.prototype.__init__, arguments);
    };
    pyjslib.__Class.prototype.__class__.__init__.unbound_method = true;
    pyjslib.__Class.prototype.__init__.instance_method = true;
    pyjslib.__Class.prototype.__class__.__init__.__name__ = '__init__';
pyjslib.__Class.prototype.__init__.__name__ = '__init__';
    pyjslib.__Class.prototype.__str___ = function() {
    return this.name;
    };
    pyjslib.__Class.prototype.__class__.__str___ = function() {
        return pyjslib.__Class.prototype.__str___.call.apply(pyjslib.__Class.prototype.__str___, arguments);
    };
    pyjslib.__Class.prototype.__class__.__str___.unbound_method = true;
    pyjslib.__Class.prototype.__str___.instance_method = true;
    pyjslib.__Class.prototype.__class__.__str___.__name__ = '__str___';
pyjslib.__Class.prototype.__str___.__name__ = '__str___';
}
pyjslib.__Class.__initialize__();
pyjslib.eq = function(a, b) {

    if (pyjslib.hasattr(a, "__cmp__")) {
        return a.__cmp__(b) == 0;
    } else if (pyjslib.hasattr(b, "__cmp__")) {
        return b.__cmp__(a) == 0;
    }
    return a == b;
    
};
pyjslib.eq.__name__ = 'eq';

pyjslib.cmp = function(a, b) {
    if (pyjslib.bool(pyjslib.hasattr(a, String('__cmp__')))) {
    return a.__cmp__(b);
    }
    else if (pyjslib.bool(pyjslib.hasattr(b, String('__cmp__')))) {
    return -b.__cmp__(a);
    }
    if (pyjslib.bool((a > b))) {
    return 1;
    }
    else if (pyjslib.bool((b > a))) {
    return -1;
    }
    else {
    return 0;
    }
    return null;
};
pyjslib.cmp.__name__ = 'cmp';

pyjslib.bool = function(v) {

    if (!v) return false;
    switch(typeof v){
    case 'boolean':
        return v;
    case 'object':
        if (v.__nonzero__){
            return v.__nonzero__();
        }else if (v.__len__){
            return v.__len__()>0;
        }
        return true;
    }
    return Boolean(v);
    
};
pyjslib.bool.__name__ = 'bool';

pyjslib.__List = function () {
}
pyjslib.List = function(data) {
    if (typeof data == 'undefined') data=null;
    var instance = new pyjslib.__List();
    if(instance.__init__) instance.__init__.apply(instance, arguments);
    return instance;
};
pyjslib.List.__name__ = 'List';

pyjslib.List.parse_kwargs = function ( __kwargs, data ) {
    if (typeof data == 'undefined')
        data=__kwargs.data;
    var __r = [data];
    return __r;
};
pyjslib.__List.__initialize__ = function () {
    if(pyjslib.__List.__was_initialized__) return;
    pyjslib.__List.__was_initialized__ = true;
    pyjs_extend(pyjslib.__List, pyjslib.__Object);
    pyjslib.__List.prototype.__class__.__new__ = pyjslib.List;
    pyjslib.__List.prototype.__class__.__name__ = 'List';
    pyjslib.__List.prototype.__init__ = function(data) {
    if (typeof data == 'undefined') data=null;

        this.l = [];
        this.extend(data);
        
    };
pyjslib.__List.prototype.__init__.parse_kwargs = function ( __kwargs, data ) {
    if (typeof data == 'undefined')
        data=__kwargs.data;
    var __r = [data];
    return __r;
};
    pyjslib.__List.prototype.__class__.__init__ = function() {
        return pyjslib.__List.prototype.__init__.call.apply(pyjslib.__List.prototype.__init__, arguments);
    };
    pyjslib.__List.prototype.__class__.__init__.unbound_method = true;
    pyjslib.__List.prototype.__init__.instance_method = true;
    pyjslib.__List.prototype.__class__.__init__.__name__ = '__init__';
pyjslib.__List.prototype.__init__.__name__ = '__init__';
    pyjslib.__List.prototype.__class__.__init__.parse_kwargs = pyjslib.__List.prototype.__init__.parse_kwargs;
    pyjslib.__List.prototype.append = function(item) {
    this.l[this.l.length] = item;
    };
    pyjslib.__List.prototype.__class__.append = function() {
        return pyjslib.__List.prototype.append.call.apply(pyjslib.__List.prototype.append, arguments);
    };
    pyjslib.__List.prototype.__class__.append.unbound_method = true;
    pyjslib.__List.prototype.append.instance_method = true;
    pyjslib.__List.prototype.__class__.append.__name__ = 'append';
pyjslib.__List.prototype.append.__name__ = 'append';
    pyjslib.__List.prototype.extend = function(data) {

        if (pyjslib.isArray(data)) {
            n = this.l.length;
            for (var i=0; i < data.length; i++) {
                this.l[n+i]=data[i];
                }
            }
        else if (pyjslib.isIteratable(data)) {
            var iter=data.__iter__();
            var i=this.l.length;
            try {
                while (true) {
                    var item=iter.next();
                    this.l[i++]=item;
                    }
                }
            catch (e) {
                if (e != pyjslib.StopIteration) throw e;
                }
            }
        
    };
    pyjslib.__List.prototype.__class__.extend = function() {
        return pyjslib.__List.prototype.extend.call.apply(pyjslib.__List.prototype.extend, arguments);
    };
    pyjslib.__List.prototype.__class__.extend.unbound_method = true;
    pyjslib.__List.prototype.extend.instance_method = true;
    pyjslib.__List.prototype.__class__.extend.__name__ = 'extend';
pyjslib.__List.prototype.extend.__name__ = 'extend';
    pyjslib.__List.prototype.remove = function(value) {

        var index=this.index(value);
        if (index<0) return false;
        this.l.splice(index, 1);
        return true;
        
    };
    pyjslib.__List.prototype.__class__.remove = function() {
        return pyjslib.__List.prototype.remove.call.apply(pyjslib.__List.prototype.remove, arguments);
    };
    pyjslib.__List.prototype.__class__.remove.unbound_method = true;
    pyjslib.__List.prototype.remove.instance_method = true;
    pyjslib.__List.prototype.__class__.remove.__name__ = 'remove';
pyjslib.__List.prototype.remove.__name__ = 'remove';
    pyjslib.__List.prototype.index = function(value, start) {
    if (typeof start == 'undefined') start=0;

        var length=this.l.length;
        for (var i=start; i<length; i++) {
            if (this.l[i]==value) {
                return i;
                }
            }
        return -1;
        
    };
pyjslib.__List.prototype.index.parse_kwargs = function ( __kwargs, value, start ) {
    if (typeof start == 'undefined')
        start=__kwargs.start;
    var __r = [value, start];
    return __r;
};
    pyjslib.__List.prototype.__class__.index = function() {
        return pyjslib.__List.prototype.index.call.apply(pyjslib.__List.prototype.index, arguments);
    };
    pyjslib.__List.prototype.__class__.index.unbound_method = true;
    pyjslib.__List.prototype.index.instance_method = true;
    pyjslib.__List.prototype.__class__.index.__name__ = 'index';
pyjslib.__List.prototype.index.__name__ = 'index';
    pyjslib.__List.prototype.__class__.index.parse_kwargs = pyjslib.__List.prototype.index.parse_kwargs;
    pyjslib.__List.prototype.insert = function(index, value) {
    var a = this.l; this.l=a.slice(0, index).concat(value, a.slice(index));
    };
    pyjslib.__List.prototype.__class__.insert = function() {
        return pyjslib.__List.prototype.insert.call.apply(pyjslib.__List.prototype.insert, arguments);
    };
    pyjslib.__List.prototype.__class__.insert.unbound_method = true;
    pyjslib.__List.prototype.insert.instance_method = true;
    pyjslib.__List.prototype.__class__.insert.__name__ = 'insert';
pyjslib.__List.prototype.insert.__name__ = 'insert';
    pyjslib.__List.prototype.pop = function(index) {
    if (typeof index == 'undefined') index=-1;

        if (index<0) index = this.l.length + index;
        var a = this.l[index];
        this.l.splice(index, 1);
        return a;
        
    };
pyjslib.__List.prototype.pop.parse_kwargs = function ( __kwargs, index ) {
    if (typeof index == 'undefined')
        index=__kwargs.index;
    var __r = [index];
    return __r;
};
    pyjslib.__List.prototype.__class__.pop = function() {
        return pyjslib.__List.prototype.pop.call.apply(pyjslib.__List.prototype.pop, arguments);
    };
    pyjslib.__List.prototype.__class__.pop.unbound_method = true;
    pyjslib.__List.prototype.pop.instance_method = true;
    pyjslib.__List.prototype.__class__.pop.__name__ = 'pop';
pyjslib.__List.prototype.pop.__name__ = 'pop';
    pyjslib.__List.prototype.__class__.pop.parse_kwargs = pyjslib.__List.prototype.pop.parse_kwargs;
    pyjslib.__List.prototype.__cmp__ = function(l) {
    if (pyjslib.bool(!(pyjslib.isinstance(l, pyjslib.__List.prototype.__class__)))) {
    return -1;
    }
    var ll =  ( pyjslib.len(this) - pyjslib.len(l) ) ;
    if (pyjslib.bool((ll != 0))) {
    return ll;
    }

        var __x = pyjslib.range(pyjslib.len(l)).__iter__();
        try {
            while (true) {
                var x = __x.next();
                
        
    ll = pyjslib.cmp(this.__getitem__(x), l.__getitem__(x));
    if (pyjslib.bool((ll != 0))) {
    return ll;
    }

            }
        } catch (e) {
            if (e.__name__ != pyjslib.StopIteration.__name__) {
                throw e;
            }
        }
        
    return 0;
    };
    pyjslib.__List.prototype.__class__.__cmp__ = function() {
        return pyjslib.__List.prototype.__cmp__.call.apply(pyjslib.__List.prototype.__cmp__, arguments);
    };
    pyjslib.__List.prototype.__class__.__cmp__.unbound_method = true;
    pyjslib.__List.prototype.__cmp__.instance_method = true;
    pyjslib.__List.prototype.__class__.__cmp__.__name__ = '__cmp__';
pyjslib.__List.prototype.__cmp__.__name__ = '__cmp__';
    pyjslib.__List.prototype.slice = function(lower, upper) {

        if (upper==null) return pyjslib.List(this.l.slice(lower));
        return pyjslib.List(this.l.slice(lower, upper));
        
    };
    pyjslib.__List.prototype.__class__.slice = function() {
        return pyjslib.__List.prototype.slice.call.apply(pyjslib.__List.prototype.slice, arguments);
    };
    pyjslib.__List.prototype.__class__.slice.unbound_method = true;
    pyjslib.__List.prototype.slice.instance_method = true;
    pyjslib.__List.prototype.__class__.slice.__name__ = 'slice';
pyjslib.__List.prototype.slice.__name__ = 'slice';
    pyjslib.__List.prototype.__getitem__ = function(index) {

        if (index<0) index = this.l.length + index;
        return this.l[index];
        
    };
    pyjslib.__List.prototype.__class__.__getitem__ = function() {
        return pyjslib.__List.prototype.__getitem__.call.apply(pyjslib.__List.prototype.__getitem__, arguments);
    };
    pyjslib.__List.prototype.__class__.__getitem__.unbound_method = true;
    pyjslib.__List.prototype.__getitem__.instance_method = true;
    pyjslib.__List.prototype.__class__.__getitem__.__name__ = '__getitem__';
pyjslib.__List.prototype.__getitem__.__name__ = '__getitem__';
    pyjslib.__List.prototype.__setitem__ = function(index, value) {
    this.l[index]=value;
    };
    pyjslib.__List.prototype.__class__.__setitem__ = function() {
        return pyjslib.__List.prototype.__setitem__.call.apply(pyjslib.__List.prototype.__setitem__, arguments);
    };
    pyjslib.__List.prototype.__class__.__setitem__.unbound_method = true;
    pyjslib.__List.prototype.__setitem__.instance_method = true;
    pyjslib.__List.prototype.__class__.__setitem__.__name__ = '__setitem__';
pyjslib.__List.prototype.__setitem__.__name__ = '__setitem__';
    pyjslib.__List.prototype.__delitem__ = function(index) {
    this.l.splice(index, 1);
    };
    pyjslib.__List.prototype.__class__.__delitem__ = function() {
        return pyjslib.__List.prototype.__delitem__.call.apply(pyjslib.__List.prototype.__delitem__, arguments);
    };
    pyjslib.__List.prototype.__class__.__delitem__.unbound_method = true;
    pyjslib.__List.prototype.__delitem__.instance_method = true;
    pyjslib.__List.prototype.__class__.__delitem__.__name__ = '__delitem__';
pyjslib.__List.prototype.__delitem__.__name__ = '__delitem__';
    pyjslib.__List.prototype.__len__ = function() {
    return this.l.length;
    };
    pyjslib.__List.prototype.__class__.__len__ = function() {
        return pyjslib.__List.prototype.__len__.call.apply(pyjslib.__List.prototype.__len__, arguments);
    };
    pyjslib.__List.prototype.__class__.__len__.unbound_method = true;
    pyjslib.__List.prototype.__len__.instance_method = true;
    pyjslib.__List.prototype.__class__.__len__.__name__ = '__len__';
pyjslib.__List.prototype.__len__.__name__ = '__len__';
    pyjslib.__List.prototype.__contains__ = function(value) {
    return (this.index(value) >= 0);
    };
    pyjslib.__List.prototype.__class__.__contains__ = function() {
        return pyjslib.__List.prototype.__contains__.call.apply(pyjslib.__List.prototype.__contains__, arguments);
    };
    pyjslib.__List.prototype.__class__.__contains__.unbound_method = true;
    pyjslib.__List.prototype.__contains__.instance_method = true;
    pyjslib.__List.prototype.__class__.__contains__.__name__ = '__contains__';
pyjslib.__List.prototype.__contains__.__name__ = '__contains__';
    pyjslib.__List.prototype.__iter__ = function() {

        var i = 0;
        var l = this.l;
        return {
            'next': function() {
                if (i >= l.length) {
                    throw pyjslib.StopIteration;
                }
                return l[i++];
            },
            '__iter__': function() {
                return this;
            }
        };
        
    };
    pyjslib.__List.prototype.__class__.__iter__ = function() {
        return pyjslib.__List.prototype.__iter__.call.apply(pyjslib.__List.prototype.__iter__, arguments);
    };
    pyjslib.__List.prototype.__class__.__iter__.unbound_method = true;
    pyjslib.__List.prototype.__iter__.instance_method = true;
    pyjslib.__List.prototype.__class__.__iter__.__name__ = '__iter__';
pyjslib.__List.prototype.__iter__.__name__ = '__iter__';
    pyjslib.__List.prototype.reverse = function() {
    this.l.reverse();
    };
    pyjslib.__List.prototype.__class__.reverse = function() {
        return pyjslib.__List.prototype.reverse.call.apply(pyjslib.__List.prototype.reverse, arguments);
    };
    pyjslib.__List.prototype.__class__.reverse.unbound_method = true;
    pyjslib.__List.prototype.reverse.instance_method = true;
    pyjslib.__List.prototype.__class__.reverse.__name__ = 'reverse';
pyjslib.__List.prototype.reverse.__name__ = 'reverse';
    pyjslib.__List.prototype.sort = function(compareFunc, keyFunc, reverse) {
    if (typeof compareFunc == 'undefined') compareFunc=null;
    if (typeof keyFunc == 'undefined') keyFunc=null;
    if (typeof reverse == 'undefined') reverse=false;
    if (pyjslib.bool(!(compareFunc))) {
    compareFunc = pyjslib.cmp;
    }
    if (pyjslib.bool((keyFunc) && (reverse))) {
thisSort1 = function(a, b) {
    return -compareFunc(keyFunc(a), keyFunc(b));
};
thisSort1.__name__ = 'thisSort1';

    this.l.sort(thisSort1);
    }
    else if (pyjslib.bool(keyFunc)) {
thisSort2 = function(a, b) {
    return compareFunc(keyFunc(a), keyFunc(b));
};
thisSort2.__name__ = 'thisSort2';

    this.l.sort(thisSort2);
    }
    else if (pyjslib.bool(reverse)) {
thisSort3 = function(a, b) {
    return -compareFunc(a, b);
};
thisSort3.__name__ = 'thisSort3';

    this.l.sort(thisSort3);
    }
    else {
    this.l.sort(compareFunc);
    }
    };
pyjslib.__List.prototype.sort.parse_kwargs = function ( __kwargs, compareFunc, keyFunc, reverse ) {
    if (typeof compareFunc == 'undefined')
        compareFunc=__kwargs.compareFunc;
    if (typeof keyFunc == 'undefined')
        keyFunc=__kwargs.keyFunc;
    if (typeof reverse == 'undefined')
        reverse=__kwargs.reverse;
    var __r = [compareFunc, keyFunc, reverse];
    return __r;
};
    pyjslib.__List.prototype.__class__.sort = function() {
        return pyjslib.__List.prototype.sort.call.apply(pyjslib.__List.prototype.sort, arguments);
    };
    pyjslib.__List.prototype.__class__.sort.unbound_method = true;
    pyjslib.__List.prototype.sort.instance_method = true;
    pyjslib.__List.prototype.__class__.sort.__name__ = 'sort';
pyjslib.__List.prototype.sort.__name__ = 'sort';
    pyjslib.__List.prototype.__class__.sort.parse_kwargs = pyjslib.__List.prototype.sort.parse_kwargs;
    pyjslib.__List.prototype.getArray = function() {
    return this.l;
    };
    pyjslib.__List.prototype.__class__.getArray = function() {
        return pyjslib.__List.prototype.getArray.call.apply(pyjslib.__List.prototype.getArray, arguments);
    };
    pyjslib.__List.prototype.__class__.getArray.unbound_method = true;
    pyjslib.__List.prototype.getArray.instance_method = true;
    pyjslib.__List.prototype.__class__.getArray.__name__ = 'getArray';
pyjslib.__List.prototype.getArray.__name__ = 'getArray';
    pyjslib.__List.prototype.__str__ = function() {
    return pyjslib.repr(this);
    };
    pyjslib.__List.prototype.__class__.__str__ = function() {
        return pyjslib.__List.prototype.__str__.call.apply(pyjslib.__List.prototype.__str__, arguments);
    };
    pyjslib.__List.prototype.__class__.__str__.unbound_method = true;
    pyjslib.__List.prototype.__str__.instance_method = true;
    pyjslib.__List.prototype.__class__.__str__.__name__ = '__str__';
pyjslib.__List.prototype.__str__.__name__ = '__str__';
}
pyjslib.__List.__initialize__();
    pyjslib.list = pyjslib.__List.prototype.__class__;
pyjslib.__Tuple = function () {
}
pyjslib.Tuple = function(data) {
    if (typeof data == 'undefined') data=null;
    var instance = new pyjslib.__Tuple();
    if(instance.__init__) instance.__init__.apply(instance, arguments);
    return instance;
};
pyjslib.Tuple.__name__ = 'Tuple';

pyjslib.Tuple.parse_kwargs = function ( __kwargs, data ) {
    if (typeof data == 'undefined')
        data=__kwargs.data;
    var __r = [data];
    return __r;
};
pyjslib.__Tuple.__initialize__ = function () {
    if(pyjslib.__Tuple.__was_initialized__) return;
    pyjslib.__Tuple.__was_initialized__ = true;
    pyjs_extend(pyjslib.__Tuple, pyjslib.__Object);
    pyjslib.__Tuple.prototype.__class__.__new__ = pyjslib.Tuple;
    pyjslib.__Tuple.prototype.__class__.__name__ = 'Tuple';
    pyjslib.__Tuple.prototype.__init__ = function(data) {
    if (typeof data == 'undefined') data=null;

        this.l = [];
        this.extend(data);
        
    };
pyjslib.__Tuple.prototype.__init__.parse_kwargs = function ( __kwargs, data ) {
    if (typeof data == 'undefined')
        data=__kwargs.data;
    var __r = [data];
    return __r;
};
    pyjslib.__Tuple.prototype.__class__.__init__ = function() {
        return pyjslib.__Tuple.prototype.__init__.call.apply(pyjslib.__Tuple.prototype.__init__, arguments);
    };
    pyjslib.__Tuple.prototype.__class__.__init__.unbound_method = true;
    pyjslib.__Tuple.prototype.__init__.instance_method = true;
    pyjslib.__Tuple.prototype.__class__.__init__.__name__ = '__init__';
pyjslib.__Tuple.prototype.__init__.__name__ = '__init__';
    pyjslib.__Tuple.prototype.__class__.__init__.parse_kwargs = pyjslib.__Tuple.prototype.__init__.parse_kwargs;
    pyjslib.__Tuple.prototype.append = function(item) {
    this.l[this.l.length] = item;
    };
    pyjslib.__Tuple.prototype.__class__.append = function() {
        return pyjslib.__Tuple.prototype.append.call.apply(pyjslib.__Tuple.prototype.append, arguments);
    };
    pyjslib.__Tuple.prototype.__class__.append.unbound_method = true;
    pyjslib.__Tuple.prototype.append.instance_method = true;
    pyjslib.__Tuple.prototype.__class__.append.__name__ = 'append';
pyjslib.__Tuple.prototype.append.__name__ = 'append';
    pyjslib.__Tuple.prototype.extend = function(data) {

        if (pyjslib.isArray(data)) {
            n = this.l.length;
            for (var i=0; i < data.length; i++) {
                this.l[n+i]=data[i];
                }
            }
        else if (pyjslib.isIteratable(data)) {
            var iter=data.__iter__();
            var i=this.l.length;
            try {
                while (true) {
                    var item=iter.next();
                    this.l[i++]=item;
                    }
                }
            catch (e) {
                if (e != pyjslib.StopIteration) throw e;
                }
            }
        
    };
    pyjslib.__Tuple.prototype.__class__.extend = function() {
        return pyjslib.__Tuple.prototype.extend.call.apply(pyjslib.__Tuple.prototype.extend, arguments);
    };
    pyjslib.__Tuple.prototype.__class__.extend.unbound_method = true;
    pyjslib.__Tuple.prototype.extend.instance_method = true;
    pyjslib.__Tuple.prototype.__class__.extend.__name__ = 'extend';
pyjslib.__Tuple.prototype.extend.__name__ = 'extend';
    pyjslib.__Tuple.prototype.remove = function(value) {

        var index=this.index(value);
        if (index<0) return false;
        this.l.splice(index, 1);
        return true;
        
    };
    pyjslib.__Tuple.prototype.__class__.remove = function() {
        return pyjslib.__Tuple.prototype.remove.call.apply(pyjslib.__Tuple.prototype.remove, arguments);
    };
    pyjslib.__Tuple.prototype.__class__.remove.unbound_method = true;
    pyjslib.__Tuple.prototype.remove.instance_method = true;
    pyjslib.__Tuple.prototype.__class__.remove.__name__ = 'remove';
pyjslib.__Tuple.prototype.remove.__name__ = 'remove';
    pyjslib.__Tuple.prototype.index = function(value, start) {
    if (typeof start == 'undefined') start=0;

        var length=this.l.length;
        for (var i=start; i<length; i++) {
            if (this.l[i]==value) {
                return i;
                }
            }
        return -1;
        
    };
pyjslib.__Tuple.prototype.index.parse_kwargs = function ( __kwargs, value, start ) {
    if (typeof start == 'undefined')
        start=__kwargs.start;
    var __r = [value, start];
    return __r;
};
    pyjslib.__Tuple.prototype.__class__.index = function() {
        return pyjslib.__Tuple.prototype.index.call.apply(pyjslib.__Tuple.prototype.index, arguments);
    };
    pyjslib.__Tuple.prototype.__class__.index.unbound_method = true;
    pyjslib.__Tuple.prototype.index.instance_method = true;
    pyjslib.__Tuple.prototype.__class__.index.__name__ = 'index';
pyjslib.__Tuple.prototype.index.__name__ = 'index';
    pyjslib.__Tuple.prototype.__class__.index.parse_kwargs = pyjslib.__Tuple.prototype.index.parse_kwargs;
    pyjslib.__Tuple.prototype.insert = function(index, value) {
    var a = this.l; this.l=a.slice(0, index).concat(value, a.slice(index));
    };
    pyjslib.__Tuple.prototype.__class__.insert = function() {
        return pyjslib.__Tuple.prototype.insert.call.apply(pyjslib.__Tuple.prototype.insert, arguments);
    };
    pyjslib.__Tuple.prototype.__class__.insert.unbound_method = true;
    pyjslib.__Tuple.prototype.insert.instance_method = true;
    pyjslib.__Tuple.prototype.__class__.insert.__name__ = 'insert';
pyjslib.__Tuple.prototype.insert.__name__ = 'insert';
    pyjslib.__Tuple.prototype.pop = function(index) {
    if (typeof index == 'undefined') index=-1;

        if (index<0) index = this.l.length + index;
        var a = this.l[index];
        this.l.splice(index, 1);
        return a;
        
    };
pyjslib.__Tuple.prototype.pop.parse_kwargs = function ( __kwargs, index ) {
    if (typeof index == 'undefined')
        index=__kwargs.index;
    var __r = [index];
    return __r;
};
    pyjslib.__Tuple.prototype.__class__.pop = function() {
        return pyjslib.__Tuple.prototype.pop.call.apply(pyjslib.__Tuple.prototype.pop, arguments);
    };
    pyjslib.__Tuple.prototype.__class__.pop.unbound_method = true;
    pyjslib.__Tuple.prototype.pop.instance_method = true;
    pyjslib.__Tuple.prototype.__class__.pop.__name__ = 'pop';
pyjslib.__Tuple.prototype.pop.__name__ = 'pop';
    pyjslib.__Tuple.prototype.__class__.pop.parse_kwargs = pyjslib.__Tuple.prototype.pop.parse_kwargs;
    pyjslib.__Tuple.prototype.__cmp__ = function(l) {
    if (pyjslib.bool(!(pyjslib.isinstance(l, pyjslib.__Tuple.prototype.__class__)))) {
    return -1;
    }
    var ll =  ( pyjslib.len(this) - pyjslib.len(l) ) ;
    if (pyjslib.bool((ll != 0))) {
    return ll;
    }

        var __x = pyjslib.range(pyjslib.len(l)).__iter__();
        try {
            while (true) {
                var x = __x.next();
                
        
    ll = pyjslib.cmp(this.__getitem__(x), l.__getitem__(x));
    if (pyjslib.bool((ll != 0))) {
    return ll;
    }

            }
        } catch (e) {
            if (e.__name__ != pyjslib.StopIteration.__name__) {
                throw e;
            }
        }
        
    return 0;
    };
    pyjslib.__Tuple.prototype.__class__.__cmp__ = function() {
        return pyjslib.__Tuple.prototype.__cmp__.call.apply(pyjslib.__Tuple.prototype.__cmp__, arguments);
    };
    pyjslib.__Tuple.prototype.__class__.__cmp__.unbound_method = true;
    pyjslib.__Tuple.prototype.__cmp__.instance_method = true;
    pyjslib.__Tuple.prototype.__class__.__cmp__.__name__ = '__cmp__';
pyjslib.__Tuple.prototype.__cmp__.__name__ = '__cmp__';
    pyjslib.__Tuple.prototype.slice = function(lower, upper) {

        if (upper==null) return pyjslib.Tuple(this.l.slice(lower));
        return pyjslib.Tuple(this.l.slice(lower, upper));
        
    };
    pyjslib.__Tuple.prototype.__class__.slice = function() {
        return pyjslib.__Tuple.prototype.slice.call.apply(pyjslib.__Tuple.prototype.slice, arguments);
    };
    pyjslib.__Tuple.prototype.__class__.slice.unbound_method = true;
    pyjslib.__Tuple.prototype.slice.instance_method = true;
    pyjslib.__Tuple.prototype.__class__.slice.__name__ = 'slice';
pyjslib.__Tuple.prototype.slice.__name__ = 'slice';
    pyjslib.__Tuple.prototype.__getitem__ = function(index) {

        if (index<0) index = this.l.length + index;
        return this.l[index];
        
    };
    pyjslib.__Tuple.prototype.__class__.__getitem__ = function() {
        return pyjslib.__Tuple.prototype.__getitem__.call.apply(pyjslib.__Tuple.prototype.__getitem__, arguments);
    };
    pyjslib.__Tuple.prototype.__class__.__getitem__.unbound_method = true;
    pyjslib.__Tuple.prototype.__getitem__.instance_method = true;
    pyjslib.__Tuple.prototype.__class__.__getitem__.__name__ = '__getitem__';
pyjslib.__Tuple.prototype.__getitem__.__name__ = '__getitem__';
    pyjslib.__Tuple.prototype.__setitem__ = function(index, value) {
    this.l[index]=value;
    };
    pyjslib.__Tuple.prototype.__class__.__setitem__ = function() {
        return pyjslib.__Tuple.prototype.__setitem__.call.apply(pyjslib.__Tuple.prototype.__setitem__, arguments);
    };
    pyjslib.__Tuple.prototype.__class__.__setitem__.unbound_method = true;
    pyjslib.__Tuple.prototype.__setitem__.instance_method = true;
    pyjslib.__Tuple.prototype.__class__.__setitem__.__name__ = '__setitem__';
pyjslib.__Tuple.prototype.__setitem__.__name__ = '__setitem__';
    pyjslib.__Tuple.prototype.__delitem__ = function(index) {
    this.l.splice(index, 1);
    };
    pyjslib.__Tuple.prototype.__class__.__delitem__ = function() {
        return pyjslib.__Tuple.prototype.__delitem__.call.apply(pyjslib.__Tuple.prototype.__delitem__, arguments);
    };
    pyjslib.__Tuple.prototype.__class__.__delitem__.unbound_method = true;
    pyjslib.__Tuple.prototype.__delitem__.instance_method = true;
    pyjslib.__Tuple.prototype.__class__.__delitem__.__name__ = '__delitem__';
pyjslib.__Tuple.prototype.__delitem__.__name__ = '__delitem__';
    pyjslib.__Tuple.prototype.__len__ = function() {
    return this.l.length;
    };
    pyjslib.__Tuple.prototype.__class__.__len__ = function() {
        return pyjslib.__Tuple.prototype.__len__.call.apply(pyjslib.__Tuple.prototype.__len__, arguments);
    };
    pyjslib.__Tuple.prototype.__class__.__len__.unbound_method = true;
    pyjslib.__Tuple.prototype.__len__.instance_method = true;
    pyjslib.__Tuple.prototype.__class__.__len__.__name__ = '__len__';
pyjslib.__Tuple.prototype.__len__.__name__ = '__len__';
    pyjslib.__Tuple.prototype.__contains__ = function(value) {
    return (this.index(value) >= 0);
    };
    pyjslib.__Tuple.prototype.__class__.__contains__ = function() {
        return pyjslib.__Tuple.prototype.__contains__.call.apply(pyjslib.__Tuple.prototype.__contains__, arguments);
    };
    pyjslib.__Tuple.prototype.__class__.__contains__.unbound_method = true;
    pyjslib.__Tuple.prototype.__contains__.instance_method = true;
    pyjslib.__Tuple.prototype.__class__.__contains__.__name__ = '__contains__';
pyjslib.__Tuple.prototype.__contains__.__name__ = '__contains__';
    pyjslib.__Tuple.prototype.__iter__ = function() {

        var i = 0;
        var l = this.l;
        return {
            'next': function() {
                if (i >= l.length) {
                    throw pyjslib.StopIteration;
                }
                return l[i++];
            },
            '__iter__': function() {
                return this;
            }
        };
        
    };
    pyjslib.__Tuple.prototype.__class__.__iter__ = function() {
        return pyjslib.__Tuple.prototype.__iter__.call.apply(pyjslib.__Tuple.prototype.__iter__, arguments);
    };
    pyjslib.__Tuple.prototype.__class__.__iter__.unbound_method = true;
    pyjslib.__Tuple.prototype.__iter__.instance_method = true;
    pyjslib.__Tuple.prototype.__class__.__iter__.__name__ = '__iter__';
pyjslib.__Tuple.prototype.__iter__.__name__ = '__iter__';
    pyjslib.__Tuple.prototype.reverse = function() {
    this.l.reverse();
    };
    pyjslib.__Tuple.prototype.__class__.reverse = function() {
        return pyjslib.__Tuple.prototype.reverse.call.apply(pyjslib.__Tuple.prototype.reverse, arguments);
    };
    pyjslib.__Tuple.prototype.__class__.reverse.unbound_method = true;
    pyjslib.__Tuple.prototype.reverse.instance_method = true;
    pyjslib.__Tuple.prototype.__class__.reverse.__name__ = 'reverse';
pyjslib.__Tuple.prototype.reverse.__name__ = 'reverse';
    pyjslib.__Tuple.prototype.sort = function(compareFunc, keyFunc, reverse) {
    if (typeof compareFunc == 'undefined') compareFunc=null;
    if (typeof keyFunc == 'undefined') keyFunc=null;
    if (typeof reverse == 'undefined') reverse=false;
    if (pyjslib.bool(!(compareFunc))) {
    compareFunc = pyjslib.cmp;
    }
    if (pyjslib.bool((keyFunc) && (reverse))) {
thisSort1 = function(a, b) {
    return -compareFunc(keyFunc(a), keyFunc(b));
};
thisSort1.__name__ = 'thisSort1';

    this.l.sort(thisSort1);
    }
    else if (pyjslib.bool(keyFunc)) {
thisSort2 = function(a, b) {
    return compareFunc(keyFunc(a), keyFunc(b));
};
thisSort2.__name__ = 'thisSort2';

    this.l.sort(thisSort2);
    }
    else if (pyjslib.bool(reverse)) {
thisSort3 = function(a, b) {
    return -compareFunc(a, b);
};
thisSort3.__name__ = 'thisSort3';

    this.l.sort(thisSort3);
    }
    else {
    this.l.sort(compareFunc);
    }
    };
pyjslib.__Tuple.prototype.sort.parse_kwargs = function ( __kwargs, compareFunc, keyFunc, reverse ) {
    if (typeof compareFunc == 'undefined')
        compareFunc=__kwargs.compareFunc;
    if (typeof keyFunc == 'undefined')
        keyFunc=__kwargs.keyFunc;
    if (typeof reverse == 'undefined')
        reverse=__kwargs.reverse;
    var __r = [compareFunc, keyFunc, reverse];
    return __r;
};
    pyjslib.__Tuple.prototype.__class__.sort = function() {
        return pyjslib.__Tuple.prototype.sort.call.apply(pyjslib.__Tuple.prototype.sort, arguments);
    };
    pyjslib.__Tuple.prototype.__class__.sort.unbound_method = true;
    pyjslib.__Tuple.prototype.sort.instance_method = true;
    pyjslib.__Tuple.prototype.__class__.sort.__name__ = 'sort';
pyjslib.__Tuple.prototype.sort.__name__ = 'sort';
    pyjslib.__Tuple.prototype.__class__.sort.parse_kwargs = pyjslib.__Tuple.prototype.sort.parse_kwargs;
    pyjslib.__Tuple.prototype.getArray = function() {
    return this.l;
    };
    pyjslib.__Tuple.prototype.__class__.getArray = function() {
        return pyjslib.__Tuple.prototype.getArray.call.apply(pyjslib.__Tuple.prototype.getArray, arguments);
    };
    pyjslib.__Tuple.prototype.__class__.getArray.unbound_method = true;
    pyjslib.__Tuple.prototype.getArray.instance_method = true;
    pyjslib.__Tuple.prototype.__class__.getArray.__name__ = 'getArray';
pyjslib.__Tuple.prototype.getArray.__name__ = 'getArray';
    pyjslib.__Tuple.prototype.__str__ = function() {
    return pyjslib.repr(this);
    };
    pyjslib.__Tuple.prototype.__class__.__str__ = function() {
        return pyjslib.__Tuple.prototype.__str__.call.apply(pyjslib.__Tuple.prototype.__str__, arguments);
    };
    pyjslib.__Tuple.prototype.__class__.__str__.unbound_method = true;
    pyjslib.__Tuple.prototype.__str__.instance_method = true;
    pyjslib.__Tuple.prototype.__class__.__str__.__name__ = '__str__';
pyjslib.__Tuple.prototype.__str__.__name__ = '__str__';
}
pyjslib.__Tuple.__initialize__();
    pyjslib.tuple = pyjslib.__Tuple.prototype.__class__;
pyjslib.__Dict = function () {
}
pyjslib.Dict = function(data) {
    if (typeof data == 'undefined') data=null;
    var instance = new pyjslib.__Dict();
    if(instance.__init__) instance.__init__.apply(instance, arguments);
    return instance;
};
pyjslib.Dict.__name__ = 'Dict';

pyjslib.Dict.parse_kwargs = function ( __kwargs, data ) {
    if (typeof data == 'undefined')
        data=__kwargs.data;
    var __r = [data];
    return __r;
};
pyjslib.__Dict.__initialize__ = function () {
    if(pyjslib.__Dict.__was_initialized__) return;
    pyjslib.__Dict.__was_initialized__ = true;
    pyjs_extend(pyjslib.__Dict, pyjslib.__Object);
    pyjslib.__Dict.prototype.__class__.__new__ = pyjslib.Dict;
    pyjslib.__Dict.prototype.__class__.__name__ = 'Dict';
    pyjslib.__Dict.prototype.__init__ = function(data) {
    if (typeof data == 'undefined') data=null;

        this.d = {};

        if (pyjslib.isArray(data)) {
            for (var i in data) {
                var item=data[i];
                this.__setitem__(item[0], item[1]);
                //var sKey=pyjslib.hash(item[0]);
                //this.d[sKey]=item[1];
                }
            }
        else if (pyjslib.isIteratable(data)) {
            var iter=data.__iter__();
            try {
                while (true) {
                    var item=iter.next();
                    this.__setitem__(item.__getitem__(0), item.__getitem__(1));
                    }
                }
            catch (e) {
                if (e != pyjslib.StopIteration) throw e;
                }
            }
        else if (pyjslib.isObject(data)) {
            for (var key in data) {
                this.__setitem__(key, data[key]);
                }
            }
        
    };
pyjslib.__Dict.prototype.__init__.parse_kwargs = function ( __kwargs, data ) {
    if (typeof data == 'undefined')
        data=__kwargs.data;
    var __r = [data];
    return __r;
};
    pyjslib.__Dict.prototype.__class__.__init__ = function() {
        return pyjslib.__Dict.prototype.__init__.call.apply(pyjslib.__Dict.prototype.__init__, arguments);
    };
    pyjslib.__Dict.prototype.__class__.__init__.unbound_method = true;
    pyjslib.__Dict.prototype.__init__.instance_method = true;
    pyjslib.__Dict.prototype.__class__.__init__.__name__ = '__init__';
pyjslib.__Dict.prototype.__init__.__name__ = '__init__';
    pyjslib.__Dict.prototype.__class__.__init__.parse_kwargs = pyjslib.__Dict.prototype.__init__.parse_kwargs;
    pyjslib.__Dict.prototype.__setitem__ = function(key, value) {

        var sKey = pyjslib.hash(key);
        this.d[sKey]=[key, value];
        
    };
    pyjslib.__Dict.prototype.__class__.__setitem__ = function() {
        return pyjslib.__Dict.prototype.__setitem__.call.apply(pyjslib.__Dict.prototype.__setitem__, arguments);
    };
    pyjslib.__Dict.prototype.__class__.__setitem__.unbound_method = true;
    pyjslib.__Dict.prototype.__setitem__.instance_method = true;
    pyjslib.__Dict.prototype.__class__.__setitem__.__name__ = '__setitem__';
pyjslib.__Dict.prototype.__setitem__.__name__ = '__setitem__';
    pyjslib.__Dict.prototype.__getitem__ = function(key) {

        var sKey = pyjslib.hash(key);
        var value=this.d[sKey];
        if (pyjslib.isUndefined(value)){
            throw pyjslib.KeyError(key);
        }
        return value[1];
        
    };
    pyjslib.__Dict.prototype.__class__.__getitem__ = function() {
        return pyjslib.__Dict.prototype.__getitem__.call.apply(pyjslib.__Dict.prototype.__getitem__, arguments);
    };
    pyjslib.__Dict.prototype.__class__.__getitem__.unbound_method = true;
    pyjslib.__Dict.prototype.__getitem__.instance_method = true;
    pyjslib.__Dict.prototype.__class__.__getitem__.__name__ = '__getitem__';
pyjslib.__Dict.prototype.__getitem__.__name__ = '__getitem__';
    pyjslib.__Dict.prototype.__nonzero__ = function() {

        for (var i in this.d){
            return true;
        }
        return false;
        
    };
    pyjslib.__Dict.prototype.__class__.__nonzero__ = function() {
        return pyjslib.__Dict.prototype.__nonzero__.call.apply(pyjslib.__Dict.prototype.__nonzero__, arguments);
    };
    pyjslib.__Dict.prototype.__class__.__nonzero__.unbound_method = true;
    pyjslib.__Dict.prototype.__nonzero__.instance_method = true;
    pyjslib.__Dict.prototype.__class__.__nonzero__.__name__ = '__nonzero__';
pyjslib.__Dict.prototype.__nonzero__.__name__ = '__nonzero__';
    pyjslib.__Dict.prototype.__len__ = function() {

        var size=0;
        for (var i in this.d) size++;
        return size;
        
    };
    pyjslib.__Dict.prototype.__class__.__len__ = function() {
        return pyjslib.__Dict.prototype.__len__.call.apply(pyjslib.__Dict.prototype.__len__, arguments);
    };
    pyjslib.__Dict.prototype.__class__.__len__.unbound_method = true;
    pyjslib.__Dict.prototype.__len__.instance_method = true;
    pyjslib.__Dict.prototype.__class__.__len__.__name__ = '__len__';
pyjslib.__Dict.prototype.__len__.__name__ = '__len__';
    pyjslib.__Dict.prototype.has_key = function(key) {
    return this.__contains__(key);
    };
    pyjslib.__Dict.prototype.__class__.has_key = function() {
        return pyjslib.__Dict.prototype.has_key.call.apply(pyjslib.__Dict.prototype.has_key, arguments);
    };
    pyjslib.__Dict.prototype.__class__.has_key.unbound_method = true;
    pyjslib.__Dict.prototype.has_key.instance_method = true;
    pyjslib.__Dict.prototype.__class__.has_key.__name__ = 'has_key';
pyjslib.__Dict.prototype.has_key.__name__ = 'has_key';
    pyjslib.__Dict.prototype.__delitem__ = function(key) {

        var sKey = pyjslib.hash(key);
        delete this.d[sKey];
        
    };
    pyjslib.__Dict.prototype.__class__.__delitem__ = function() {
        return pyjslib.__Dict.prototype.__delitem__.call.apply(pyjslib.__Dict.prototype.__delitem__, arguments);
    };
    pyjslib.__Dict.prototype.__class__.__delitem__.unbound_method = true;
    pyjslib.__Dict.prototype.__delitem__.instance_method = true;
    pyjslib.__Dict.prototype.__class__.__delitem__.__name__ = '__delitem__';
pyjslib.__Dict.prototype.__delitem__.__name__ = '__delitem__';
    pyjslib.__Dict.prototype.__contains__ = function(key) {

        var sKey = pyjslib.hash(key);
        return (pyjslib.isUndefined(this.d[sKey])) ? false : true;
        
    };
    pyjslib.__Dict.prototype.__class__.__contains__ = function() {
        return pyjslib.__Dict.prototype.__contains__.call.apply(pyjslib.__Dict.prototype.__contains__, arguments);
    };
    pyjslib.__Dict.prototype.__class__.__contains__.unbound_method = true;
    pyjslib.__Dict.prototype.__contains__.instance_method = true;
    pyjslib.__Dict.prototype.__class__.__contains__.__name__ = '__contains__';
pyjslib.__Dict.prototype.__contains__.__name__ = '__contains__';
    pyjslib.__Dict.prototype.keys = function() {

        var keys=new pyjslib.List();
        for (var key in this.d) {
            keys.append(this.d[key][0]);
        }
        return keys;
        
    };
    pyjslib.__Dict.prototype.__class__.keys = function() {
        return pyjslib.__Dict.prototype.keys.call.apply(pyjslib.__Dict.prototype.keys, arguments);
    };
    pyjslib.__Dict.prototype.__class__.keys.unbound_method = true;
    pyjslib.__Dict.prototype.keys.instance_method = true;
    pyjslib.__Dict.prototype.__class__.keys.__name__ = 'keys';
pyjslib.__Dict.prototype.keys.__name__ = 'keys';
    pyjslib.__Dict.prototype.values = function() {

        var values=new pyjslib.List();
        for (var key in this.d) values.append(this.d[key][1]);
        return values;
        
    };
    pyjslib.__Dict.prototype.__class__.values = function() {
        return pyjslib.__Dict.prototype.values.call.apply(pyjslib.__Dict.prototype.values, arguments);
    };
    pyjslib.__Dict.prototype.__class__.values.unbound_method = true;
    pyjslib.__Dict.prototype.values.instance_method = true;
    pyjslib.__Dict.prototype.__class__.values.__name__ = 'values';
pyjslib.__Dict.prototype.values.__name__ = 'values';
    pyjslib.__Dict.prototype.items = function() {

        var items = new pyjslib.List();
        for (var key in this.d) {
          var kv = this.d[key];
          items.append(new pyjslib.List(kv))
          }
          return items;
        
    };
    pyjslib.__Dict.prototype.__class__.items = function() {
        return pyjslib.__Dict.prototype.items.call.apply(pyjslib.__Dict.prototype.items, arguments);
    };
    pyjslib.__Dict.prototype.__class__.items.unbound_method = true;
    pyjslib.__Dict.prototype.items.instance_method = true;
    pyjslib.__Dict.prototype.__class__.items.__name__ = 'items';
pyjslib.__Dict.prototype.items.__name__ = 'items';
    pyjslib.__Dict.prototype.__iter__ = function() {
    return this.keys().__iter__();
    };
    pyjslib.__Dict.prototype.__class__.__iter__ = function() {
        return pyjslib.__Dict.prototype.__iter__.call.apply(pyjslib.__Dict.prototype.__iter__, arguments);
    };
    pyjslib.__Dict.prototype.__class__.__iter__.unbound_method = true;
    pyjslib.__Dict.prototype.__iter__.instance_method = true;
    pyjslib.__Dict.prototype.__class__.__iter__.__name__ = '__iter__';
pyjslib.__Dict.prototype.__iter__.__name__ = '__iter__';
    pyjslib.__Dict.prototype.iterkeys = function() {
    return this.__iter__();
    };
    pyjslib.__Dict.prototype.__class__.iterkeys = function() {
        return pyjslib.__Dict.prototype.iterkeys.call.apply(pyjslib.__Dict.prototype.iterkeys, arguments);
    };
    pyjslib.__Dict.prototype.__class__.iterkeys.unbound_method = true;
    pyjslib.__Dict.prototype.iterkeys.instance_method = true;
    pyjslib.__Dict.prototype.__class__.iterkeys.__name__ = 'iterkeys';
pyjslib.__Dict.prototype.iterkeys.__name__ = 'iterkeys';
    pyjslib.__Dict.prototype.itervalues = function() {
    return this.values().__iter__();
    };
    pyjslib.__Dict.prototype.__class__.itervalues = function() {
        return pyjslib.__Dict.prototype.itervalues.call.apply(pyjslib.__Dict.prototype.itervalues, arguments);
    };
    pyjslib.__Dict.prototype.__class__.itervalues.unbound_method = true;
    pyjslib.__Dict.prototype.itervalues.instance_method = true;
    pyjslib.__Dict.prototype.__class__.itervalues.__name__ = 'itervalues';
pyjslib.__Dict.prototype.itervalues.__name__ = 'itervalues';
    pyjslib.__Dict.prototype.iteritems = function() {
    return this.items().__iter__();
    };
    pyjslib.__Dict.prototype.__class__.iteritems = function() {
        return pyjslib.__Dict.prototype.iteritems.call.apply(pyjslib.__Dict.prototype.iteritems, arguments);
    };
    pyjslib.__Dict.prototype.__class__.iteritems.unbound_method = true;
    pyjslib.__Dict.prototype.iteritems.instance_method = true;
    pyjslib.__Dict.prototype.__class__.iteritems.__name__ = 'iteritems';
pyjslib.__Dict.prototype.iteritems.__name__ = 'iteritems';
    pyjslib.__Dict.prototype.setdefault = function(key, default_value) {
    if (pyjslib.bool(!this.__contains__(key))) {
    this.__setitem__(key, default_value);
    }
    };
    pyjslib.__Dict.prototype.__class__.setdefault = function() {
        return pyjslib.__Dict.prototype.setdefault.call.apply(pyjslib.__Dict.prototype.setdefault, arguments);
    };
    pyjslib.__Dict.prototype.__class__.setdefault.unbound_method = true;
    pyjslib.__Dict.prototype.setdefault.instance_method = true;
    pyjslib.__Dict.prototype.__class__.setdefault.__name__ = 'setdefault';
pyjslib.__Dict.prototype.setdefault.__name__ = 'setdefault';
    pyjslib.__Dict.prototype.get = function(key, default_) {
    if (typeof default_ == 'undefined') default_=null;
    if (pyjslib.bool(!this.__contains__(key))) {
    return default_;
    }
    return this.__getitem__(key);
    };
pyjslib.__Dict.prototype.get.parse_kwargs = function ( __kwargs, key, default_ ) {
    if (typeof default_ == 'undefined')
        default_=__kwargs.default_;
    var __r = [key, default_];
    return __r;
};
    pyjslib.__Dict.prototype.__class__.get = function() {
        return pyjslib.__Dict.prototype.get.call.apply(pyjslib.__Dict.prototype.get, arguments);
    };
    pyjslib.__Dict.prototype.__class__.get.unbound_method = true;
    pyjslib.__Dict.prototype.get.instance_method = true;
    pyjslib.__Dict.prototype.__class__.get.__name__ = 'get';
pyjslib.__Dict.prototype.get.__name__ = 'get';
    pyjslib.__Dict.prototype.__class__.get.parse_kwargs = pyjslib.__Dict.prototype.get.parse_kwargs;
    pyjslib.__Dict.prototype.update = function(d) {

        var __temp_k = d.iteritems().__iter__();
        try {
            while (true) {
                var temp_k = __temp_k.next();
                
                var k = temp_k.__getitem__(0);
                
                var v = temp_k.__getitem__(1);
                
        
    this.__setitem__(k, v);

            }
        } catch (e) {
            if (e.__name__ != pyjslib.StopIteration.__name__) {
                throw e;
            }
        }
        
    };
    pyjslib.__Dict.prototype.__class__.update = function() {
        return pyjslib.__Dict.prototype.update.call.apply(pyjslib.__Dict.prototype.update, arguments);
    };
    pyjslib.__Dict.prototype.__class__.update.unbound_method = true;
    pyjslib.__Dict.prototype.update.instance_method = true;
    pyjslib.__Dict.prototype.__class__.update.__name__ = 'update';
pyjslib.__Dict.prototype.update.__name__ = 'update';
    pyjslib.__Dict.prototype.getObject = function() {
    return this.d;
    };
    pyjslib.__Dict.prototype.__class__.getObject = function() {
        return pyjslib.__Dict.prototype.getObject.call.apply(pyjslib.__Dict.prototype.getObject, arguments);
    };
    pyjslib.__Dict.prototype.__class__.getObject.unbound_method = true;
    pyjslib.__Dict.prototype.getObject.instance_method = true;
    pyjslib.__Dict.prototype.__class__.getObject.__name__ = 'getObject';
pyjslib.__Dict.prototype.getObject.__name__ = 'getObject';
    pyjslib.__Dict.prototype.copy = function() {
    return pyjslib.Dict(this.items());
    };
    pyjslib.__Dict.prototype.__class__.copy = function() {
        return pyjslib.__Dict.prototype.copy.call.apply(pyjslib.__Dict.prototype.copy, arguments);
    };
    pyjslib.__Dict.prototype.__class__.copy.unbound_method = true;
    pyjslib.__Dict.prototype.copy.instance_method = true;
    pyjslib.__Dict.prototype.__class__.copy.__name__ = 'copy';
pyjslib.__Dict.prototype.copy.__name__ = 'copy';
    pyjslib.__Dict.prototype.__str__ = function() {
    return pyjslib.repr(this);
    };
    pyjslib.__Dict.prototype.__class__.__str__ = function() {
        return pyjslib.__Dict.prototype.__str__.call.apply(pyjslib.__Dict.prototype.__str__, arguments);
    };
    pyjslib.__Dict.prototype.__class__.__str__.unbound_method = true;
    pyjslib.__Dict.prototype.__str__.instance_method = true;
    pyjslib.__Dict.prototype.__class__.__str__.__name__ = '__str__';
pyjslib.__Dict.prototype.__str__.__name__ = '__str__';
}
pyjslib.__Dict.__initialize__();
    pyjslib.dict = pyjslib.__Dict.prototype.__class__;
pyjslib.range = function() {

    var start = 0;
    var stop = 0;
    var step = 1;

    if (arguments.length == 2) {
        start = arguments[0];
        stop = arguments[1];
        }
    else if (arguments.length == 3) {
        start = arguments[0];
        stop = arguments[1];
        step = arguments[2];
        }
    else if (arguments.length>0) stop = arguments[0];

    return {
        'next': function() {
            if ((step > 0 && start >= stop) || (step < 0 && start <= stop)) throw pyjslib.StopIteration;
            var rval = start;
            start += step;
            return rval;
            },
        '__iter__': function() {
            return this;
            }
        }
    
};
pyjslib.range.__name__ = 'range';

pyjslib.slice = function(object, lower, upper) {

    if (pyjslib.isString(object)) {
        if (lower < 0) {
           lower = object.length + lower;
        }
        if (upper < 0) {
           upper = object.length + upper;
        }
        if (pyjslib.isNull(upper)) upper=object.length;
        return object.substring(lower, upper);
    }
    if (pyjslib.isObject(object) && object.slice)
        return object.slice(lower, upper);

    return null;
    
};
pyjslib.slice.__name__ = 'slice';

pyjslib.str = function(text) {

    if (pyjslib.hasattr(text,"__str__")) {
        return text.__str__();
    }
    return String(text);
    
};
pyjslib.str.__name__ = 'str';

pyjslib.ord = function(x) {
    if (pyjslib.bool((pyjslib.isString(x)) && ((pyjslib.len(x) === 1)))) {

            return x.charCodeAt(0);
        
    }
    else {

            throw pyjslib.TypeError();
        
    }
    return null;
};
pyjslib.ord.__name__ = 'ord';

pyjslib.chr = function(x) {

        return String.fromCharCode(x)
    
};
pyjslib.chr.__name__ = 'chr';

pyjslib.is_basetype = function(x) {

       var t = typeof(x);
       return t == 'boolean' ||
       t == 'function' ||
       t == 'number' ||
       t == 'string' ||
       t == 'undefined'
       ;
    
};
pyjslib.is_basetype.__name__ = 'is_basetype';

pyjslib.get_pyjs_classtype = function(x) {

       if (pyjslib.hasattr(x, "__class__"))
           if (pyjslib.hasattr(x.__class__, "__new__"))
               var src = x.__class__.__name__;
               return src;
       return null;
    
};
pyjslib.get_pyjs_classtype.__name__ = 'get_pyjs_classtype';

pyjslib.repr = function(x) {

       if (x === null)
           return "null";

       if (x === undefined)
           return "undefined";

       var t = typeof(x);

        //alert("repr typeof " + t + " : " + x);

       if (t == "boolean")
           return x.toString();

       if (t == "function")
           return "<function " + x.toString() + ">";

       if (t == "number")
           return x.toString();

       if (t == "string") {
           if (x.indexOf("'") == -1)
               return "'" + x + "'";
           if (x.indexOf('"') == -1)
               return '"' + x + '"';
           var s = x.replace(new RegExp('"', "g"), '\\"');
           return '"' + s + '"';
       };

       if (t == "undefined")
           return "undefined";

       // If we get here, x is an object.  See if it's a Pyjamas class.

       if (!pyjslib.hasattr(x, "__init__"))
           return "<" + x.toString() + ">";

       // Handle the common Pyjamas data types.

       var constructor = "UNKNOWN";

       constructor = pyjslib.get_pyjs_classtype(x);

        //alert("repr constructor: " + constructor);

       if (constructor == "Tuple") {
           var contents = x.getArray();
           var s = "(";
           for (var i=0; i < contents.length; i++) {
               s += pyjslib.repr(contents[i]);
               if (i < contents.length - 1)
                   s += ", ";
           };
           s += ")"
           return s;
       };

       if (constructor == "List") {
           var contents = x.getArray();
           var s = "[";
           for (var i=0; i < contents.length; i++) {
               s += pyjslib.repr(contents[i]);
               if (i < contents.length - 1)
                   s += ", ";
           };
           s += "]"
           return s;
       };

       if (constructor == "Dict") {
           var keys = new Array();
           for (var key in x.d)
               keys.push(key);

           var s = "{";
           for (var i=0; i<keys.length; i++) {
               var key = keys[i]
               s += pyjslib.repr(key) + ": " + pyjslib.repr(x.d[key]);
               if (i < keys.length-1)
                   s += ", "
           };
           s += "}";
           return s;
       };

       // If we get here, the class isn't one we know -> return the class name.
       // Note that we replace underscores with dots so that the name will
       // (hopefully!) look like the original Python name.

       //var s = constructor.replace(new RegExp('_', "g"), '.');
       return "<" + constructor + " object>";
    
};
pyjslib.repr.__name__ = 'repr';

pyjslib.float = function(text) {

    return parseFloat(text);
    
};
pyjslib.float.__name__ = 'float';

pyjslib.int = function(text, radix) {
    if (typeof radix == 'undefined') radix=0;

    return parseInt(text, radix);
    
};
pyjslib.int.__name__ = 'int';

pyjslib.int.parse_kwargs = function ( __kwargs, text, radix ) {
    if (typeof radix == 'undefined')
        radix=__kwargs.radix;
    var __r = [text, radix];
    return __r;
};
pyjslib.len = function(object) {

    if (object==null) return 0;
    if (pyjslib.isObject(object) && object.__len__) return object.__len__();
    return object.length;
    
};
pyjslib.len.__name__ = 'len';

pyjslib.isinstance = function(object_, classinfo) {
    if (pyjslib.bool(pyjslib.isUndefined(object_))) {
    return false;
    }
    if (pyjslib.bool(!(pyjslib.isObject(object_)))) {
    return false;
    }
    if (pyjslib.bool(pyjslib._isinstance(classinfo, pyjslib.__Tuple.prototype.__class__))) {

        var __ci = classinfo.__iter__();
        try {
            while (true) {
                var ci = __ci.next();
                
        
    if (pyjslib.bool(pyjslib.isinstance(object_, ci))) {
    return true;
    }

            }
        } catch (e) {
            if (e.__name__ != pyjslib.StopIteration.__name__) {
                throw e;
            }
        }
        
    return false;
    }
    else {
    return pyjslib._isinstance(object_, classinfo);
    }
    return null;
};
pyjslib.isinstance.__name__ = 'isinstance';

pyjslib._isinstance = function(object_, classinfo) {
    if (pyjslib.bool(!(pyjslib.isObject(object_)))) {
    return false;
    }

    if (object_.__class__){
        var res =  object_ instanceof classinfo.constructor;
        return res;
    }
    return false;
    
};
pyjslib._isinstance.__name__ = '_isinstance';

pyjslib.getattr = function(obj, name, default_) {
    if (typeof default_ == 'undefined') default_=null;

    if ((!pyjslib.isObject(obj))||(pyjslib.isUndefined(obj[name]))){
        if (pyjslib.isUndefined(default_)){
            throw pyjslib.AttributeError(obj, name);
        }else{
        return default_;
        }
    }
    if (!pyjslib.isFunction(obj[name])) return obj[name];
    var fnwrap = function() {
        var args = [];
        for (var i = 0; i < arguments.length; i++) {
          args.push(arguments[i]);
        }
        return obj[name].apply(obj,args);
        }
    fnwrap.__name__ = name;
    return fnwrap;
    
};
pyjslib.getattr.__name__ = 'getattr';

pyjslib.getattr.parse_kwargs = function ( __kwargs, obj, name, default_ ) {
    if (typeof default_ == 'undefined')
        default_=__kwargs.default_;
    var __r = [obj, name, default_];
    return __r;
};
pyjslib.setattr = function(obj, name, value) {

    if (!pyjslib.isObject(obj)) return null;

    obj[name] = value;

    
};
pyjslib.setattr.__name__ = 'setattr';

pyjslib.hasattr = function(obj, name) {

    if (!pyjslib.isObject(obj)) return false;
    if (pyjslib.isUndefined(obj[name])) return false;

    return true;
    
};
pyjslib.hasattr.__name__ = 'hasattr';

pyjslib.dir = function(obj) {

    var properties=new pyjslib.List();
    for (property in obj) properties.append(property);
    return properties;
    
};
pyjslib.dir.__name__ = 'dir';

pyjslib.filter = function(obj, method, sequence) {
    if (typeof sequence == 'undefined') sequence=null;
    var items = new pyjslib.List([]);
    if (pyjslib.bool((sequence === null))) {
    sequence = method;
    method = obj;

        var __item = sequence.__iter__();
        try {
            while (true) {
                var item = __item.next();
                
        
    if (pyjslib.bool(method(item))) {
    items.append(item);
    }

            }
        } catch (e) {
            if (e.__name__ != pyjslib.StopIteration.__name__) {
                throw e;
            }
        }
        
    }
    else {

        var __item = sequence.__iter__();
        try {
            while (true) {
                var item = __item.next();
                
        
    if (pyjslib.bool(method.call(obj, item))) {
    items.append(item);
    }

            }
        } catch (e) {
            if (e.__name__ != pyjslib.StopIteration.__name__) {
                throw e;
            }
        }
        
    }
    return items;
};
pyjslib.filter.__name__ = 'filter';

pyjslib.filter.parse_kwargs = function ( __kwargs, obj, method, sequence ) {
    if (typeof sequence == 'undefined')
        sequence=__kwargs.sequence;
    var __r = [obj, method, sequence];
    return __r;
};
pyjslib.map = function(obj, method, sequence) {
    if (typeof sequence == 'undefined') sequence=null;
    var items = new pyjslib.List([]);
    if (pyjslib.bool((sequence === null))) {
    sequence = method;
    method = obj;

        var __item = sequence.__iter__();
        try {
            while (true) {
                var item = __item.next();
                
        
    items.append(method(item));

            }
        } catch (e) {
            if (e.__name__ != pyjslib.StopIteration.__name__) {
                throw e;
            }
        }
        
    }
    else {

        var __item = sequence.__iter__();
        try {
            while (true) {
                var item = __item.next();
                
        
    items.append(method.call(obj, item));

            }
        } catch (e) {
            if (e.__name__ != pyjslib.StopIteration.__name__) {
                throw e;
            }
        }
        
    }
    return items;
};
pyjslib.map.__name__ = 'map';

pyjslib.map.parse_kwargs = function ( __kwargs, obj, method, sequence ) {
    if (typeof sequence == 'undefined')
        sequence=__kwargs.sequence;
    var __r = [obj, method, sequence];
    return __r;
};
pyjslib.enumerate = function(sequence) {
    var enumeration = new pyjslib.List([]);
    var nextIndex = 0;

        var __item = sequence.__iter__();
        try {
            while (true) {
                var item = __item.next();
                
        
    enumeration.append(new pyjslib.List([nextIndex, item]));
    nextIndex =  ( nextIndex + 1 ) ;

            }
        } catch (e) {
            if (e.__name__ != pyjslib.StopIteration.__name__) {
                throw e;
            }
        }
        
    return enumeration;
};
pyjslib.enumerate.__name__ = 'enumerate';

pyjslib.min = function() {
    var sequence = new pyjslib.Tuple();
    for(var __va_arg=0; __va_arg < arguments.length; __va_arg++) {
        var __arg = arguments[__va_arg];
        sequence.append(__arg);
    }
    var minValue = null;

        var __item = sequence.__iter__();
        try {
            while (true) {
                var item = __item.next();
                
        
    if (pyjslib.bool((minValue === null))) {
    minValue = item;
    }
    else if (pyjslib.bool((item < minValue))) {
    minValue = item;
    }

            }
        } catch (e) {
            if (e.__name__ != pyjslib.StopIteration.__name__) {
                throw e;
            }
        }
        
    return minValue;
};
pyjslib.min.__name__ = 'min';

pyjslib.max = function() {
    var sequence = new pyjslib.Tuple();
    for(var __va_arg=0; __va_arg < arguments.length; __va_arg++) {
        var __arg = arguments[__va_arg];
        sequence.append(__arg);
    }
    var maxValue = null;

        var __item = sequence.__iter__();
        try {
            while (true) {
                var item = __item.next();
                
        
    if (pyjslib.bool((maxValue === null))) {
    maxValue = item;
    }
    else if (pyjslib.bool((item > maxValue))) {
    maxValue = item;
    }

            }
        } catch (e) {
            if (e.__name__ != pyjslib.StopIteration.__name__) {
                throw e;
            }
        }
        
    return maxValue;
};
pyjslib.max.__name__ = 'max';

    pyjslib.next_hash_id = 0;
pyjslib.hash = function(obj) {

    if (obj == null) return null;

    if (obj.$H) return obj.$H;
    if (obj.__hash__) return obj.__hash__();
    if (obj.constructor == String || obj.constructor == Number || obj.constructor == Date) return obj;

    obj.$H = ++pyjslib.next_hash_id;
    return obj.$H;
    
};
pyjslib.hash.__name__ = 'hash';

pyjslib.isObject = function(a) {

    return (a != null && (typeof a == 'object')) || pyjslib.isFunction(a);
    
};
pyjslib.isObject.__name__ = 'isObject';

pyjslib.isFunction = function(a) {

    return typeof a == 'function';
    
};
pyjslib.isFunction.__name__ = 'isFunction';

pyjslib.isString = function(a) {

    return typeof a == 'string';
    
};
pyjslib.isString.__name__ = 'isString';

pyjslib.isNull = function(a) {

    return typeof a == 'object' && !a;
    
};
pyjslib.isNull.__name__ = 'isNull';

pyjslib.isArray = function(a) {

    return pyjslib.isObject(a) && a.constructor == Array;
    
};
pyjslib.isArray.__name__ = 'isArray';

pyjslib.isUndefined = function(a) {

    return typeof a == 'undefined';
    
};
pyjslib.isUndefined.__name__ = 'isUndefined';

pyjslib.isIteratable = function(a) {

    return pyjslib.isString(a) || (pyjslib.isObject(a) && a.__iter__);
    
};
pyjslib.isIteratable.__name__ = 'isIteratable';

pyjslib.isNumber = function(a) {

    return typeof a == 'number' && isFinite(a);
    
};
pyjslib.isNumber.__name__ = 'isNumber';

pyjslib.toJSObjects = function(x) {
    if (pyjslib.bool(pyjslib.isArray(x))) {

        var result = [];
        for(var k=0; k < x.length; k++) {
           var v = x[k];
           var tv = pyjslib.toJSObjects(v);
           result.push(tv);
        }
        return result;
        
    }
    if (pyjslib.bool(pyjslib.isObject(x))) {
    if (pyjslib.bool(pyjslib.isinstance(x, pyjslib.__Dict.prototype.__class__))) {

            var o = x.getObject();
            var result = {};
            for (var i in o) {
               result[o[i][0].toString()] = o[i][1];
            }
            return pyjslib.toJSObjects(result)
            
    }
    else if (pyjslib.bool(pyjslib.isinstance(x, pyjslib.__List.prototype.__class__))) {
    return pyjslib.toJSObjects(x.l);
    }
    else if (pyjslib.bool(pyjslib.hasattr(x, String('__class__')))) {
    return x;
    }
    }
    if (pyjslib.bool(pyjslib.isObject(x))) {

        var result = {};
        for(var k in x) {
            var v = x[k];
            var tv = pyjslib.toJSObjects(v)
            result[k] = tv;
            }
            return result;
         
    }
    return x;
};
pyjslib.toJSObjects.__name__ = 'toJSObjects';

pyjslib.printFunc = function(objs) {

    if ($wnd.console==undefined)  return;
    var s = "";
    for(var i=0; i < objs.length; i++) {
        if(s != "") s += " ";
        s += objs[i];
    }
    console.debug(s)
    
};
pyjslib.printFunc.__name__ = 'printFunc';

pyjslib.type = function(clsname, bases, methods) {
    if (typeof bases == 'undefined') bases=null;
    if (typeof methods == 'undefined') methods=null;
 var mths = {}; 
    if (pyjslib.bool(methods)) {

        var __k = methods.keys().__iter__();
        try {
            while (true) {
                var k = __k.next();
                
        
    var _mth = methods.__getitem__(k);
 mths[k] = _mth; 

            }
        } catch (e) {
            if (e.__name__ != pyjslib.StopIteration.__name__) {
                throw e;
            }
        }
        
    }
 var bss = null; 
    if (pyjslib.bool(bases)) {
bss = bases.l;
    }
 return pyjs_type(clsname, bss, mths); 
};
pyjslib.type.__name__ = 'type';

pyjslib.type.parse_kwargs = function ( __kwargs, clsname, bases, methods ) {
    if (typeof bases == 'undefined')
        bases=__kwargs.bases;
    if (typeof methods == 'undefined')
        methods=__kwargs.methods;
    var __r = [clsname, bases, methods];
    return __r;
};
return this;

}; /* end pyjslib */ 

var svguilib = function (__mod_name__) {
    if(svguilib.__was_initialized__) return;
    svguilib.__was_initialized__ = true;
if (__mod_name__ == null) __mod_name__ = 'svguilib';
svguilib.__name__ = __mod_name__;
svguilib.__button = function () {
}
svguilib.button = function(parent, id, args) {
    var instance = new svguilib.__button();
    if(instance.__init__) instance.__init__.apply(instance, arguments);
    return instance;
};
svguilib.button.__name__ = 'button';

svguilib.__button.__initialize__ = function () {
    if(svguilib.__button.__was_initialized__) return;
    svguilib.__button.__was_initialized__ = true;
    pyjs_extend(svguilib.__button, pyjslib.__Object);
    svguilib.__button.prototype.__class__.__new__ = svguilib.button;
    svguilib.__button.prototype.__class__.__name__ = 'button';
    svguilib.__button.prototype.__init__ = function(parent, id, args) {
    this.parent = parent;
    this.id = id;
    this.back_elt = getSVGElementById(args.back_id);
    this.sele_elt = getSVGElementById(args.sele_id);
    this.toggle = args.toggle;
    this.active = args.active;
    if (pyjslib.bool((args.state != svguilib.__button.prototype.__class__.undefined))) {
    this.state = args.state;
    }
    else {
    this.state = false;
    }
    this.dragging = false;
    if (pyjslib.bool(this.toggle)) {
    this.up = !(this.state);
    }
    else {
    this.up = true;
    }
    if (pyjslib.bool(this.active)) {
    this.back_elt.addEventListener(String('mouseup'), this, false);
    this.back_elt.addEventListener(String('mousedown'), this, false);
    this.back_elt.addEventListener(String('mouseover'), this, false);
    this.back_elt.addEventListener(String('mouseout'), this, false);
    this.sele_elt.addEventListener(String('mouseup'), this, false);
    this.sele_elt.addEventListener(String('mousedown'), this, false);
    this.sele_elt.addEventListener(String('mouseover'), this, false);
    this.sele_elt.addEventListener(String('mouseout'), this, false);
    }
    blockSVGElementDrag(this.back_elt);
    blockSVGElementDrag(this.sele_elt);
    this.updateElements();
    };
    svguilib.__button.prototype.__class__.__init__ = function() {
        return svguilib.__button.prototype.__init__.call.apply(svguilib.__button.prototype.__init__, arguments);
    };
    svguilib.__button.prototype.__class__.__init__.unbound_method = true;
    svguilib.__button.prototype.__init__.instance_method = true;
    svguilib.__button.prototype.__class__.__init__.__name__ = '__init__';
svguilib.__button.prototype.__init__.__name__ = '__init__';
    svguilib.__button.prototype.updateElements = function() {
    if (pyjslib.bool(this.up)) {
    this.sele_elt.setAttribute(String('display'), String('none'));
    this.back_elt.removeAttribute(String('display'));
    }
    else {
    this.sele_elt.removeAttribute(String('display'));
    this.back_elt.setAttribute(String('display'), String('none'));
    }
    };
    svguilib.__button.prototype.__class__.updateElements = function() {
        return svguilib.__button.prototype.updateElements.call.apply(svguilib.__button.prototype.updateElements, arguments);
    };
    svguilib.__button.prototype.__class__.updateElements.unbound_method = true;
    svguilib.__button.prototype.updateElements.instance_method = true;
    svguilib.__button.prototype.__class__.updateElements.__name__ = 'updateElements';
svguilib.__button.prototype.updateElements.__name__ = 'updateElements';
    svguilib.__button.prototype.updateValues = function(values) {
    if (pyjslib.bool((values.state != this.state))) {
    this.state = values.state;
    this.up = !(this.state);
    if (pyjslib.bool(this.toggle)) {
    updateAttr(this.id, String('state'), this.state);
    }
    this.updateElements();
    }
    };
    svguilib.__button.prototype.__class__.updateValues = function() {
        return svguilib.__button.prototype.updateValues.call.apply(svguilib.__button.prototype.updateValues, arguments);
    };
    svguilib.__button.prototype.__class__.updateValues.unbound_method = true;
    svguilib.__button.prototype.updateValues.instance_method = true;
    svguilib.__button.prototype.__class__.updateValues.__name__ = 'updateValues';
svguilib.__button.prototype.updateValues.__name__ = 'updateValues';
    svguilib.__button.prototype.handleEvent = function(evt) {
    if (pyjslib.bool(pyjslib.eq(evt.type, String('mousedown')))) {
    evt.stopPropagation();
    setCurrentObject(this);
    this.dragging = true;
    if (pyjslib.bool(this.toggle)) {
    this.up = this.state;
    }
    else {
    this.up = false;
    this.state = true;
    updateAttr(this.id, String('state'), this.state);
    }
    this.updateElements();
    }
    if (pyjslib.bool((isCurrentObject(this)) && (this.dragging))) {
    if (pyjslib.bool((pyjslib.eq(evt.type, String('mouseover'))) && (this.toggle))) {
    this.up = this.state;
    this.updateElements();
    }
    else if (pyjslib.bool((pyjslib.eq(evt.type, String('mouseout'))) && (this.toggle))) {
    this.up = !(this.state);
    this.updateElements();
    }
    else if (pyjslib.bool(pyjslib.eq(evt.type, String('mouseup')))) {
    evt.stopPropagation();
    if (pyjslib.bool((this.toggle) && (pyjslib.eq(this.up, this.state)))) {
    this.state = !(this.state);
    updateAttr(this.id, String('state'), this.state);
    }
    else if (pyjslib.bool(!(this.toggle))) {
    this.up = true;
    this.state = false;
    updateAttr(this.id, String('state'), this.state);
    this.updateElements();
    }
    this.dragging = false;
    }
    }
    };
    svguilib.__button.prototype.__class__.handleEvent = function() {
        return svguilib.__button.prototype.handleEvent.call.apply(svguilib.__button.prototype.handleEvent, arguments);
    };
    svguilib.__button.prototype.__class__.handleEvent.unbound_method = true;
    svguilib.__button.prototype.handleEvent.instance_method = true;
    svguilib.__button.prototype.__class__.handleEvent.__name__ = 'handleEvent';
svguilib.__button.prototype.handleEvent.__name__ = 'handleEvent';
}
svguilib.__button.__initialize__();
svguilib.__textControl = function () {
}
svguilib.textControl = function(parent, id, args) {
    var instance = new svguilib.__textControl();
    if(instance.__init__) instance.__init__.apply(instance, arguments);
    return instance;
};
svguilib.textControl.__name__ = 'textControl';

svguilib.__textControl.__initialize__ = function () {
    if(svguilib.__textControl.__was_initialized__) return;
    svguilib.__textControl.__was_initialized__ = true;
    pyjs_extend(svguilib.__textControl, pyjslib.__Object);
    svguilib.__textControl.prototype.__class__.__new__ = svguilib.textControl;
    svguilib.__textControl.prototype.__class__.__name__ = 'textControl';
    svguilib.__textControl.prototype.__init__ = function(parent, id, args) {
    this.parent = parent;
    this.id = id;
    this.back_elt = getSVGElementById(args.back_id);
    if (pyjslib.bool((args.text != svguilib.__textControl.prototype.__class__.undefined))) {
    this.text = args.text;
    }
    else {
    this.text = String('');
    }
    this.updateElements();
    };
    svguilib.__textControl.prototype.__class__.__init__ = function() {
        return svguilib.__textControl.prototype.__init__.call.apply(svguilib.__textControl.prototype.__init__, arguments);
    };
    svguilib.__textControl.prototype.__class__.__init__.unbound_method = true;
    svguilib.__textControl.prototype.__init__.instance_method = true;
    svguilib.__textControl.prototype.__class__.__init__.__name__ = '__init__';
svguilib.__textControl.prototype.__init__.__name__ = '__init__';
    svguilib.__textControl.prototype.updateValues = function(values) {
    if (pyjslib.bool((values.text != this.value))) {
    this.text = values.text;
    updateAttr(this.id, String('text'), this.text);
    this.updateElements();
    }
    };
    svguilib.__textControl.prototype.__class__.updateValues = function() {
        return svguilib.__textControl.prototype.updateValues.call.apply(svguilib.__textControl.prototype.updateValues, arguments);
    };
    svguilib.__textControl.prototype.__class__.updateValues.unbound_method = true;
    svguilib.__textControl.prototype.updateValues.instance_method = true;
    svguilib.__textControl.prototype.__class__.updateValues.__name__ = 'updateValues';
svguilib.__textControl.prototype.updateValues.__name__ = 'updateValues';
    svguilib.__textControl.prototype.updateElements = function() {
    this.back_elt.firstChild.firstChild.textContent = this.text;
    };
    svguilib.__textControl.prototype.__class__.updateElements = function() {
        return svguilib.__textControl.prototype.updateElements.call.apply(svguilib.__textControl.prototype.updateElements, arguments);
    };
    svguilib.__textControl.prototype.__class__.updateElements.unbound_method = true;
    svguilib.__textControl.prototype.updateElements.instance_method = true;
    svguilib.__textControl.prototype.__class__.updateElements.__name__ = 'updateElements';
svguilib.__textControl.prototype.updateElements.__name__ = 'updateElements';
    svguilib.__textControl.prototype.handleEvent = function(evt) {
    };
    svguilib.__textControl.prototype.__class__.handleEvent = function() {
        return svguilib.__textControl.prototype.handleEvent.call.apply(svguilib.__textControl.prototype.handleEvent, arguments);
    };
    svguilib.__textControl.prototype.__class__.handleEvent.unbound_method = true;
    svguilib.__textControl.prototype.handleEvent.instance_method = true;
    svguilib.__textControl.prototype.__class__.handleEvent.__name__ = 'handleEvent';
svguilib.__textControl.prototype.handleEvent.__name__ = 'handleEvent';
}
svguilib.__textControl.__initialize__();
return this;

}; /* end svguilib */ 

pyjslib();
svguilib();
json_parse = (function () {

// This is a function that can parse a JSON text, producing a JavaScript
// data structure. It is a simple, recursive descent parser. It does not use
// eval or regular expressions, so it can be used as a model for implementing
// a JSON parser in other languages.

// We are defining the function inside of another function to avoid creating
// global variables.

    var at,     // The index of the current character
        ch,     // The current character
        escapee = {
            '"':  '"',
            '\\': '\\',
            '/':  '/',
            b:    '\b',
            f:    '\f',
            n:    '\n',
            r:    '\r',
            t:    '\t'
        },
        text,

        error = function (m) {

// Call error when something is wrong.

            throw {
                name:    'SyntaxError',
                message: m,
                at:      at,
                text:    text
            };
        },

        next = function (c) {

// If a c parameter is provided, verify that it matches the current character.

            if (c && c !== ch) {
                error("Expected '" + c + "' instead of '" + ch + "'");
            }

// Get the next character. When there are no more characters,
// return the empty string.

            ch = text.charAt(at);
            at += 1;
            return ch;
        },

        number = function () {

// Parse a number value.

            var number,
                string = '';

            if (ch === '-') {
                string = '-';
                next('-');
            }
            while (ch >= '0' && ch <= '9') {
                string += ch;
                next();
            }
            if (ch === '.') {
                string += '.';
                while (next() && ch >= '0' && ch <= '9') {
                    string += ch;
                }
            }
            if (ch === 'e' || ch === 'E') {
                string += ch;
                next();
                if (ch === '-' || ch === '+') {
                    string += ch;
                    next();
                }
                while (ch >= '0' && ch <= '9') {
                    string += ch;
                    next();
                }
            }
            number = +string;
            if (isNaN(number)) {
                error("Bad number");
            } else {
                return number;
            }
        },

        string = function () {

// Parse a string value.

            var hex,
                i,
                string = '',
                uffff;

// When parsing for string values, we must look for " and \ characters.

            if (ch === '"') {
                while (next()) {
                    if (ch === '"') {
                        next();
                        return string;
                    } else if (ch === '\\') {
                        next();
                        if (ch === 'u') {
                            uffff = 0;
                            for (i = 0; i < 4; i += 1) {
                                hex = parseInt(next(), 16);
                                if (!isFinite(hex)) {
                                    break;
                                }
                                uffff = uffff * 16 + hex;
                            }
                            string += String.fromCharCode(uffff);
                        } else if (typeof escapee[ch] === 'string') {
                            string += escapee[ch];
                        } else {
                            break;
                        }
                    } else {
                        string += ch;
                    }
                }
            }
            error("Bad string");
        },

        white = function () {

// Skip whitespace.

            while (ch && ch <= ' ') {
                next();
            }
        },

        word = function () {

// true, false, or null.

            switch (ch) {
            case 't':
                next('t');
                next('r');
                next('u');
                next('e');
                return true;
            case 'f':
                next('f');
                next('a');
                next('l');
                next('s');
                next('e');
                return false;
            case 'n':
                next('n');
                next('u');
                next('l');
                next('l');
                return null;
            }
            error("Unexpected '" + ch + "'");
        },

        value,  // Place holder for the value function.

        array = function () {

// Parse an array value.

            var array = [];

            if (ch === '[') {
                next('[');
                white();
                if (ch === ']') {
                    next(']');
                    return array;   // empty array
                }
                while (ch) {
                    array.push(value());
                    white();
                    if (ch === ']') {
                        next(']');
                        return array;
                    }
                    next(',');
                    white();
                }
            }
            error("Bad array");
        },

        object = function () {

// Parse an object value.

            var key,
                object = {};

            if (ch === '{') {
                next('{');
                white();
                if (ch === '}') {
                    next('}');
                    return object;   // empty object
                }
                while (ch) {
                    key = string();
                    white();
                    next(':');
                    if (Object.hasOwnProperty.call(object, key)) {
                        error('Duplicate key "' + key + '"');
                    }
                    object[key] = value();
                    white();
                    if (ch === '}') {
                        next('}');
                        return object;
                    }
                    next(',');
                    white();
                }
            }
            error("Bad object");
        };

    value = function () {

// Parse a JSON value. It could be an object, an array, a string, a number,
// or a word.

        white();
        switch (ch) {
        case '{':
            return object();
        case '[':
            return array();
        case '"':
            return string();
        case '-':
            return number();
        default:
            return ch >= '0' && ch <= '9' ? number() : word();
        }
    };

// Return the json_parse function. It will have access to all of the above
// functions and variables.

    return function (source, reviver) {
        var result;

        text = source;
        at = 0;
        ch = ' ';
        result = value();
        white();
        if (ch) {
            error("Syntax error");
        }

// If there is a reviver function, we recursively walk the new structure,
// passing each name/value pair to the reviver function for possible
// transformation, starting with a temporary root object that holds the result
// in an empty key. If there is not a reviver function, we simply return the
// result.

        return typeof reviver === 'function' ? (function walk(holder, key) {
            var k, v, value = holder[key];
            if (value && typeof value === 'object') {
                for (k in value) {
                    if (Object.hasOwnProperty.call(value, k)) {
                        v = walk(value, k);
                        if (v !== undefined) {
                            value[k] = v;
                        } else {
                            delete value[k];
                        }
                    }
                }
            }
            return reviver.call(holder, key, value);
        }({'': result}, '')) : result;
    };
}());
// import Nevow.Athena
// import Divmod.Base

function updateAttr(id, param, value) {
  Nevow.Athena.Widget.fromAthenaID(1).callRemote('HMIexec', 'setattr', id, param, value);
}

var svguiWidgets = new Array();

var currentObject = null;
function setCurrentObject(obj) {
	currentObject = obj;
}
function isCurrentObject(obj) {
	return currentObject == obj;
}

function getSVGElementById(id) {
	return document.getElementById(id);
}

function blockSVGElementDrag(element) {
	element.addEventListener("draggesture", function(event){event.stopPropagation()}, true);
}

LiveSVGPage.LiveSVGWidget = Nevow.Athena.Widget.subclass('LiveSVGPage.LiveSVGWidget');
LiveSVGPage.LiveSVGWidget.methods(

    function handleEvent(self, evt) {
        if (currentObject != null) {
            currentObject.handleEvent(evt);
        }
    },

    function receiveData(self, data){
        dataReceived = json_parse(data);
        gadget = svguiWidgets[dataReceived.id]
        if (gadget) {
        	gadget.updateValues(json_parse(dataReceived.kwargs));
        }
        //console.log("OBJET : " + dataReceived.back_id + " STATE : " + newState);
    },
    
    function init(self, arg1){
        //console.log("Object received : " + arg1);
        for (ind in arg1) {
            gad = json_parse(arg1[ind]);
            args = json_parse(gad.kwargs);
            gadget = new svguilib[gad.__class__](self, gad.id, args);
            svguiWidgets[gadget.id]=gadget;
            //console.log('GADGET :' + gadget);
        }
        var elements = document.getElementsByTagName("svg");
        for (var i = 0; i < elements.length; i++) {
        	elements[i].addEventListener("mouseup", self, false);
        }
        //console.log("SVGUIWIDGETS : " + svguiWidgets);
    }
);
