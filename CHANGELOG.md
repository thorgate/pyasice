# pyasice Changelog

## v.1.0.2

* Fixed an issue with `Container` and `ZipFile` in Python pre-3.8.

  When the name of a file added to container contained a non-ASCII character,
  a consequent `read()` of this file failed with an error:
  ```
  zipfile.BadZipFile: File name in directory 'FILE' and header b'FILE' differ.
  ```
  After closing the ZipFile, reading files was OK.
  
  As a solution, now the container is opened in read-only mode and all write operations
  are performed after closing the read-only zipfile, opening it in append mode and
  closing it again.
  
* Added a public property `zip_file` to the `Container` instance which uses a cached
  read only zip file handle, opening it if necessary.

* Added a public property `zip_writer` to the `Container` instance which opens 
  an appendable zip file handle, clearing the `zip_file` cache.
  
* Merged the `verify_container` and `_verify_container_contents` methods
  because the latter made little sense on its own as a private method.
  
* Replaced `_add_mimetype()` with `_create_container()` which creates and initializes
  the buffer in one single place.

## v.1.0.1

* Reordered requests to OCSP and TSA in the `utils.finalize_signature` function.
  That was necessary for Esteid services because sometimes the signed container could not be verified,
  due to an error:
  ```
  TimeStamp time is greater than OCSP producedAt TS: 2020-11-05T15:27:59Z OCSP: 20201105152758Z
  ``` 

## v.1.0

* Initial version. Supports creating and validating XAdES signatures with Estonian ID services. 
