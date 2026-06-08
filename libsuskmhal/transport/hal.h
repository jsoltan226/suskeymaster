#ifndef SUSKEYMASTER_KMHAL_HAL_H_
#define SUSKEYMASTER_KMHAL_HAL_H_

#ifndef SUSKEYMASTER_BUILD_HOST

/**
 * HAL - A wrapper around HIDL & AIDL HAL handles and transactions.
 */

#include "binder.h"
#include "parcel.h"
#include "status.h"
#include <core/int.h>
#include <core/log.h>

#ifdef __cplusplus
extern "C" {
#endif /* __cplusplus */

/* Opaque reference to a HAL strong pointer and associated data */
struct kmhal_sp;

/**
 * Allocates and initializes a new HAL strong pointer struct.
 * The returned struct is empty and not ready for use.
 * You are probably looking for `kmhal_sp_new_get`.
 *
 * @return A new HAL strong pointer struct, or NULL on allocation failure.
 */
struct kmhal_sp * kmhal_sp_new_empty(void);

/**
 * Allocates a new HIDL HAL strong pointer struct, and tries to initialize
 * it with a handle to the requested HAL instance.
 *
 * @param fqname The fully qualified name of the HAL interface, e.g.
 *  "android.hardware.keymaster@3.0::IKeymasterDevice".
 *
 * @param instname The name of the HAL instance (e.g. "default" or "strongbox").
 *  If NULL, "default" is used.
 *
 * @param opt_existing_binder Optionally, an existing valid binder device
 *  context. If NULL, a new one will be allocated and initialized internally.
 *
 * @param owns_existing_binder Whether or not the provided binder device context
 *  should be automatically destroyed in `kmhal_sp_destroy`.
 *  Ignored if `opt_existing_binder` is NULL.
 *
 * @return On success, a new HAL strong pointer initialized with a handle
 *  to the requested HAL, or NULL on failure.
 */
struct kmhal_sp *
kmhal_hidl_sp_new_get(const char *fqname, const char *instname,
                      struct kmhal_binder_ctx *opt_existing_binder,
                      bool owns_existing_binder);

/**
 * Allocates a new AIDL HAL strong pointer struct, and tries to initialize
 * it with a handle to the requested HAL instance.
 *
 * @param fqname The fully qualified name of the HAL interface, e.g.
 *  "android.hardware.security.keymint.IKeyMintDevice".
 *
 * @param instname The name of the HAL instance (e.g. "default" or "strongbox").
 *  If NULL, "default" is used.
 *
 * @param opt_existing_binder Optionally, an existing valid binder device
 *  context. If NULL, a new one will be allocated and initialized internally.
 *
 * @param owns_existing_binder Whether or not the provided binder device context
 *  should be automatically destroyed in `kmhal_sp_destroy`.
 *  Ignored if `opt_existing_binder` is NULL.
 *
 * @return On success, a new HAL strong pointer initialized with a handle
 *  to the requested HAL, or NULL on failure.
 */
struct kmhal_sp *
kmhal_aidl_sp_new_get(const char *fqname, const char *instname,
                      struct kmhal_binder_ctx *opt_existing_binder,
                      bool owns_existing_binder);

/**
 * Destroys the HAL strong pointer struct and any associated resources.
 * Sets `*hal_p` to NULL afterwards.
 *
 * @param hal_p A pointer to the strong pointer struct to destroy
 */
void kmhal_sp_destroy(struct kmhal_sp **hal_p);

/**
 * Attempts to ping the HAL instance.
 *
 * @param hal The HAL instance to ping.
 *
 * @return OK if successful, anything else otherwise.
 */
enum kmhal_android_status kmhal_ping(struct kmhal_sp *hal);

/**
 * Calls the special `getInterfaceVersion` on an AIDL HAL.
 * Invalid for HIDL HALs.
 *
 * @param the HAL instance whose interface version to query.
 *
 * @param out_interface_version Output pointer for the returned
 *  interface version. May be NULL.
 *
 * @return OK if successful, anything else otherwise.
 */
enum kmhal_android_status
kmhal_get_aidl_interface_version(struct kmhal_sp *hal,
                                 i32 *out_interface_version);

/**
 * The types of data that can be serialized/deserialized
 * from/to a binder transaction.
 */
enum kmhal_arg_type {
    /**
     * Invalid value.
     */
    KMHAL_ARG_INVALID_,

    /**
     * A primitive type, e.g. an integer, serialized inline.
     * Basically anything that fits in the word size,
     * that doesn't require to be passed as a pointer.
     */
    KMHAL_ARG_PRIMITIVE,

    /**
     * Fixed-size object which might contain pointers
     * to scatter-gather buffers and other binder buffer objects.
     * Used with HIDL.
     *
     * Note: The object itself is fixed size, but that doesn't apply
     * to buffers it might have pointers to.
     * For example, an hidl_string is ALWAYS layed out as follows:
     *  [buffer: 8 bytes][length: 4 bytes][owns_buffer + pad: 4 bytes]
     * But `buffer` is a pointer to an sg buffer, the size of which
     * is determined by the `length` member (+1 for the '\0' terminator).
     * This `buffer` is a binder-remapped pointer to some other memory.
     *
     * After being read, these objects are valid until
     * the next binder transaction.
     */
    KMHAL_ARG_BUFFER_OBJECT,

    /**
     * Arbitrary size data which is serialized inline in the parcel.
     * The data's size is assumed to be serialized somewhere alongside it
     * or to be otherwise known, and it ought to be validated during parsing.
     * Mostly used with AIDL.
     *
     * After being read, these objects are valid until
     * the next binder transaction.
     */
    KMHAL_ARG_INLINE_DATA,

    /**
     * Invalid value.
     */
    KMHAL_ARG_MAX_
};

/**
 * A function that serializes a primitive value (`KMHAL_ARG_PRIMITIVE`)
 * into a parcel.
 *
 * @param p The parcel to write into.
 *
 * @param val User-provided; The immediate value to serialize.
 *
 * @param size User-provided; The size of the primitive type, e.g. 4 for a u32.
 */
typedef void (*kmhal_arg_write_primitive_proc_t)
    (struct kmhal_parcel *p, u64 val, size_t size);

/**
 * A function that serializes the given data of the `KMHAL_ARG_BUFFER_OBJECT`
 * into a parcel. It should abort on `size` mismatch.
 *
 * @param p The parcel to write into.
 *
 * @param data User-provided; A pointer to the object data.
 *  Must not be NULL if @size is > 0.
 *
 * @param size User-provided; The size of @data.
 */
typedef void (*kmhal_arg_write_buffer_obj_proc_t)
    (struct kmhal_parcel *p, const void *data, size_t size);

/**
 * A function that serializes the given `KMHAL_ARG_INLINE_DATA` into a parcel.
 * It should abort if it dectects that the provided arguments are invalid.
 *
 * @param p The parcel to write into.
 *
 * @param data User-provided; A pointer to the data to serialize.
 */
typedef void (*kmhal_arg_write_inline_data_proc_t)
    (struct kmhal_parcel *p, const void *data);

/**
 * Descriptor that enables the serialization of an argument to a HAL call.
 *
 * For example, for the HIDL IKeymasterDevice::addRngEntropy
 * the `hidl_vec<uint8_t> data` (of type `KMHAL_ARG_BUFFER_OBJECT`)
 *
 * would be the only argument. Used with `kmhal_call`.
 */
struct kmhal_arg_write_desc {
    const char *name; /* The name of the argument. Must not be NULL. */

    /* The type of the to-be-serialized argument.
     * A member of the below union should be chosen and initialized
     * according to the value of this field.
     * Must be a valid `enum kmhal_arg_type`. */
    enum kmhal_arg_type type;

    union kmhal_arg_write {
        struct kmhal_arg_write_primitive {
            /* The function that serializes the given primitive type.
             * The `User-provided` arguments passed to it should be set below.
             * Must not be NULL. */
            kmhal_arg_write_primitive_proc_t proc;

            /* See the definition of `kmhal_arg_write_buffer_obj_proc_t`
             * and `KMHAL_ARG_PRIMITIVE`. */
            u64 val;
            size_t size;
        } p;

        struct kmhal_arg_write_buffer_obj {
            /* The function that serializes the given buffer object data.
             * The `User-provided` arguments passed to it should be set below.
             * Must not be NULL. */
            kmhal_arg_write_buffer_obj_proc_t proc;

            /* See the definition of `kmhal_arg_write_buffer_obj_proc_t`
             * and `KMHAL_ARG_BUFFER_OBJECT`. */
            const void *data;
            size_t size;
        } b;

        struct kmhal_arg_write_inline_data {
            /* The function that serializes the given data inline.
             * The `User-provided` arguments passed to it should be set below.
             * Must not be NULL. */
            kmhal_arg_write_inline_data_proc_t proc;

            /* See the definition of `kmhal_arg_write_inline_data_proc_t`
             * and `KMHAL_ARG_INLINE_DATA`. */
            const void *data;
        } i;
    } arg;
};

/**
 * A function that reads a `KMHAL_ARG_PRIMITIVE` value from a parcel.
 * It should only write to `out` and `off_p` on success.
 *
 * @param p The parcel to read from.
 *
 * @param off_p A pointer to the offset into the parcel's read buffer,
 *  which on successful read should be incremented to point past the read data.
 *
 * @param out User-provided; Output pointer. Must not be NULL if @size is > 0.
 *
 * @param size User-provided; The size of the primitive type, e.g. 4 for a u32.
 *
 * @return 0 on success, non-zero on read failure.
 */
typedef int (*kmhal_arg_parse_primitive_proc_t)
    (const struct kmhal_parcel *p, size_t *off_p, void *out, size_t size);

/**
 * A function that reads a `KMHAL_ARG_BUFFER_OBJECT` from a parcel.
 * It should only write to `out_p` and `off_p` on success.
 *
 * @param p The parcel to read from.
 *
 * @param off_p A pointer to the offset into the parcel's read buffer,
 *  which on successful read should be incremented to point past the read data.
 *
 * @param out_p User-provided; Pointer to output pointer.
 *  On successful read, it should contain a const pointer into binder memory
 *  which is valid until the next transaction.
 *  Must not be NULL if @exp_out_size > 0.
 *  The given `*out_p` should be initialized to NULL.
 *
 * @param exp_out_size User-provided; The expected size of the object to read.
 *  Note: This applies to the object itself, not any buffers
 *  it might have pointers to. See `KMHAL_ARG_BUFFER_OBJECT`.
 *
 * @return 0 on success, non-zero on size mismatch or other failure.
 *
 * See `kmhal_call` and `enum kmhal_arg_type`.
 */
typedef int (*kmhal_arg_parse_buffer_obj_proc_t)
    (const struct kmhal_parcel *p, size_t *off_p,
        const void **out_p, size_t exp_out_size);

/**
 * A function that reads and parses `KMHAL_ARG_INLINE_DATA` from a parcel.
 * The format and size of the data should be validated by this function.
 *
 * @param p The parcel to read from.
 *
 * @param off_p A pointer to the offset into the parcel's read buffer,
 *  which on successful read should be incremented to point past the read data.
 *
 * @param out User-provided; Output pointer to data of size @out_size.
 *  On successful read, the function should parse the data
 *  and write the result in the implied expected format into @out.
 *  Must be non-null if @size is > 0.
 *
 * @param out_size User-provided; Size of the output buffer @out.
 *
 * @return 0 on success, non-zero on read/parsing failure or @size mismatch.
 */
typedef int (*kmhal_arg_parse_inline_data_proc_t)
    (const struct kmhal_parcel *p, size_t *off_p, void *out, size_t out_size);

/**
 * Descriptor that enables deserialization of an output (returned)
 * argument from a HAL call.
 *
 * For example, for the HIDL IKeymasterDevice::addRngEntropy
 * the returned `ErrorCode` (of type `KMHAL_ARG_PRIMITIVE`)
 * would be the only output argument.
 *
 * Used with `kmhal_call`.
 */
struct kmhal_arg_parse_desc {
    const char *name; /* The name of the argument. Must not be NULL. */

    /* The type of the to-be-deserialized argument.
     * A member of the below union should be chosen and initialized
     * according to the value of this field.
     * Must be a valid `enum kmhal_arg_type`. */
    enum kmhal_arg_type type;

    union kmhal_parse_arg {
        struct kmhal_arg_parse_primitive {
            /* The function that deserializes the given primitive type.
             * The `User-provided` arguments passed to it should be set below.
             * Must not be NULL. */
            kmhal_arg_parse_primitive_proc_t proc;

            /* See the definition of `kmhal_arg_parse_buffer_obj_proc_t`
             * and `KMHAL_ARG_PRIMITIVE`. */
            void *out;
            size_t size;
        } p;

        struct kmhal_arg_parse_buffer_obj {
            /* The function that deserializes the given buffer object data.
             * The `User-provided` arguments passed to it should be set below.
             * Must not be NULL. */
            kmhal_arg_parse_buffer_obj_proc_t proc;

            /* See the definition of `kmhal_arg_parse_buffer_obj_proc_t`
             * and `KMHAL_ARG_BUFFER_OBJECT`. */
            const void **out_p;
            size_t exp_out_size;
        } b;

        struct kmhal_arg_parse_inline_data {
            /* The function that deserializes the given data inline.
             * The `User-provided` arguments passed to it should be set below.
             * Must not be NULL. */
            kmhal_arg_parse_inline_data_proc_t proc;

            /* See the definition of `kmhal_arg_parse_inline_data_proc_t`
             * and `KMHAL_ARG_INLINE_DATA`. */
            void *out;
            size_t size;
        } i;
    } arg;
};

/**
 * Calls a given method on a HAL using provided arguments
 * and parses the returned data.
 *
 * @param hal The HAL to transact with.
 *
 * @param cmd The command ID of the HAL method.
 *
 * @param in_args A list of descriptors of the method's arguments.
 *  Can be NULL only if the method doesn't take any arguments,
 *  in which case @n_in_args should also be set to 0.
 *
 * @param n_in_args The number of members of the @in_args array.
 *
 * @param in_args A list of descriptors of the method's return values.
 *  Can be NULL only if the method doesn't return anything,
 *  in which case @n_out_args should also be set to 0.
 *
 * @param n_out_args The number of members of the @in_args array.
 *
 * @return OK on success, anything else on failure.
 *  See `enum kmhal_android_status`.
 */
enum kmhal_android_status
kmhal_call(struct kmhal_sp *hal, u32 cmd,
           const struct kmhal_arg_write_desc *in_args, u32 n_in_args,
           struct kmhal_arg_parse_desc *out_args, u32 n_out_args);

/** Some useful universal functions
 * for serializing/deserializing common types of data **/

void kmhal_arg_write_u32(struct kmhal_parcel *p, u64 val, size_t size);
void kmhal_arg_write_u64(struct kmhal_parcel *p, u64 val, size_t size);

int kmhal_arg_parse_u32(const struct kmhal_parcel *p, size_t *off_p,
                        void *out, size_t size);
int kmhal_arg_parse_u64(const struct kmhal_parcel *p, size_t *off_p,
                        void *out, size_t size);

/**
 * A getter for the currently used binder device context.
 *
 * @param hal The HAL strong pointer struct.
 *
 * @param opt_out_owns_binder An optional output pointer for whether
 *  the binder device context is set to be cleaned up automatically
 *  during destruction.
 *
 * @return @hal's binder device context.
 */
struct kmhal_binder_ctx *
kmhal_get_binder(struct kmhal_sp *hal, bool *opt_out_owns_binder);

/**
 * A setter for the binder device context.
 * If @hal already contains and owns an existing context,
 * it is destroyed before being overwritten by the new one.
 *
 * @param hal The HAL strong pointer struct.
 *
 * @param binder The new binder device context.
 *
 * @param owns_binder Whether @binder should be set to be cleaned up
 *  automatically during @hal's destruction.
 */
void kmhal_set_binder(struct kmhal_sp *hal,
                      struct kmhal_binder_ctx *binder, bool owns_binder);

/**
 * A getter for the currently used HAL binder handle.
 *
 * @param hal The HAL strong pointer struct.
 *
 * @param opt_out_owns_handle An optional output pointer for whether
 *  the binder handle is set to be released automatically
 *  during @hal's destruction.
 *
 * @return @hal's binder device context.
 */
u32 kmhal_get_handle(const struct kmhal_sp *hal, bool *opt_out_owns_handle);

/**
 * A setter for the HAL binder handle.
 *
 * @param hal The HAL strong pointer struct.
 * If @hal already contains and owns an existing handle,
 * the references on it are dropped before the overwrite with the new one.
 *
 * @param handle The new HAL binder handle.
 *
 * @param owns_handle Whether references to @handle should be set to be
 *  automatically dropped during @hal's destruction.
 */
void kmhal_set_handle(struct kmhal_sp *hal, u32 handle, bool owns_handle);

/**
 * A getter for the fully qualified interface name of the HAL
 * referenced by the strong pointer struct.
 *
 * @param hal The HAL strong pointer struct.
 *
 * @return The fully qualified interface name of @hal, e.g.
 *  "android.hardware.keymaster@3.0::IKeymasterDevice".
 */
const char * kmhal_get_fqname(const struct kmhal_sp *hal);

/**
 * A setter for the fully qualified interface name of the HAL
 * referenced by the strong pointer struct.
 *
 * @param hal The HAL strong pointer struct.
 *
 * @param fqname The new fully qualified interface name, e.g.
 *  "android.hardware.keymaster@3.0::IKeymasterDevice".
 */
void kmhal_set_fqname(struct kmhal_sp *hal, const char *fqname);

/**
 * A getter for the instance name of the HAL
 * referenced by the strong pointer struct.
 *
 * @param hal The HAL strong pointer struct.
 *
 * @return The instance name of @hal, e.g. "default".
 */
const char * kmhal_get_instname(const struct kmhal_sp *hal);

/**
 * A setter for the instance name of the HAL
 * referenced by the strong pointer struct.
 *
 * @param hal The HAL strong pointer struct.
 *
 * @param fqname The new instance name, e.g. "default".
 */
void kmhal_set_instname(struct kmhal_sp *hal, const char *instname);


#ifdef __cplusplus
} /* extern "C" */
#endif /* __cplusplus */

/** Helpers for C++ cause that language sucks **/
#ifdef __cplusplus
namespace suskeymaster {
namespace kmhal {
namespace transport {

/* For std::unique_ptr */
static inline void kmhal_sp_deleter(struct kmhal_sp *hal)
{
    kmhal_sp_destroy(&hal);
}

template<typename T> static inline struct kmhal_arg_write_desc
init_write(const char *name, T val, kmhal_arg_write_primitive_proc_t proc)
{
    static_assert(sizeof(T) <= sizeof(u64), "Too large for primitive type");
    struct kmhal_arg_write_desc ret;

    ret.name = name;
    ret.type = KMHAL_ARG_PRIMITIVE;
    ret.arg.p.proc = proc;
    ret.arg.p.val = static_cast<u64>(val);
    ret.arg.p.size = sizeof(T);

    return ret;
}

template<typename T> static inline struct kmhal_arg_parse_desc
init_parse(const char *name, T *out, kmhal_arg_parse_primitive_proc_t proc)
{
    static_assert(sizeof(T) <= sizeof(u64), "Too large for primitive type");
    struct kmhal_arg_parse_desc ret;

    ret.name = name;
    ret.type = KMHAL_ARG_PRIMITIVE;
    ret.arg.p.proc = proc;
    ret.arg.p.out = out;
    ret.arg.p.size = sizeof(T);

    return ret;
}

template<typename T> static inline struct kmhal_arg_write_desc
init_write(const char *name, const T *data,
           kmhal_arg_write_buffer_obj_proc_t proc)
{
    struct kmhal_arg_write_desc ret;

    ret.name = name;
    ret.type = KMHAL_ARG_BUFFER_OBJECT;
    ret.arg.b.proc = proc;
    ret.arg.b.data = data;
    ret.arg.b.size = sizeof(T);

    return ret;
}

template<typename T> static inline struct kmhal_arg_parse_desc
init_parse(const char *name, const T **out_p,
           kmhal_arg_parse_buffer_obj_proc_t proc)
{
    struct kmhal_arg_parse_desc ret;

    ret.name = name;
    ret.type = KMHAL_ARG_BUFFER_OBJECT;
    ret.arg.b.proc = proc;
    ret.arg.b.out_p = reinterpret_cast<const void **>(out_p);
    ret.arg.b.exp_out_size = sizeof(T);

    return ret;
}

template<typename T> static inline struct kmhal_arg_write_desc
init_write_i(const char *name, const T *data,
             kmhal_arg_write_inline_data_proc_t proc)
{
    struct kmhal_arg_write_desc ret;

    ret.name = name;
    ret.type = KMHAL_ARG_INLINE_DATA;
    ret.arg.i.proc = proc;
    ret.arg.i.data = data;

    return ret;
}

template<typename T> static inline struct kmhal_arg_parse_desc
init_parse_i(const char *name, T *out,
             kmhal_arg_parse_inline_data_proc_t proc)
{
    struct kmhal_arg_parse_desc ret;

    ret.name = name;
    ret.type = KMHAL_ARG_INLINE_DATA;
    ret.arg.i.proc = proc;
    ret.arg.i.out = out;
    ret.arg.i.size = sizeof(T);

    return ret;
}
} /* namespace transport */
} /* namespace kmhal */
} /* namespace suskeymaster */
#endif /* __cplusplus */

#endif /* SUSKEYMASTER_BUILD_HOST */

#endif /* SUSKEYMASTER_KMHAL_HAL_H_ */
