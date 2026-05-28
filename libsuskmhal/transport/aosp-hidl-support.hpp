/** Code stole from AOSP headers (hidl/HidlSupport.h).
 * Includes only code relevant for hidl_string and hidl_vec<T>. **/

/*
 * Copyright (C) 2016 The Android Open Source Project
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#ifndef ANDROID_HIDL_SUPPORT_H
#define ANDROID_HIDL_SUPPORT_H

#include <algorithm>
#include <array>
#include <cassert>
#include <exception>
#include <iterator>
#include <map>
#include <sstream>
#include <stddef.h>
#include <tuple>
#include <type_traits>
#include <vector>
#include <cstdint>
#include <cstring>
#include <iostream>

namespace android {
namespace hardware {
namespace details {

// tag for pure interfaces (e.x. IFoo)
struct i_tag {};

// tag for server interfaces (e.x. BnHwFoo)
struct bnhw_tag {};

// tag for proxy interfaces (e.x. BpHwFoo)
struct bphw_tag {};

// tag for passthrough interfaces (e.x. BsFoo)
struct bs_tag {};

//Templated classes can use the below method
//to avoid creating dependencies on liblog.
inline void logAlwaysFatal(const char *message)
{
    std::cerr << message << std::endl;
    std::terminate();
}

// Returns VNDK-SP hw path according to "ro.vndk.version"
#if defined(__LP64__)
std::string getVndkSpHwPath(const char* lib = "lib64");
#else
std::string getVndkSpHwPath(const char* lib = "lib");
#endif

// Explicitly invokes the parameterized element's destructor;
// intended to be used alongside the placement new operator.
template<typename T>
void destructElement(T* element) {
    if (element != nullptr) {
        element->~T();
    }
}

// HIDL client/server code should *NOT* use this class.
//
// hidl_pointer wraps a pointer without taking ownership,
// and stores it in a union with a uint64_t. This ensures
// that we always have enough space to store a pointer,
// regardless of whether we're running in a 32-bit or 64-bit
// process.
template<typename T>
struct hidl_pointer {
    hidl_pointer()
        : _pad(0) {
        static_assert(sizeof(*this) == 8, "wrong size");
    }
    hidl_pointer(T* ptr) : hidl_pointer() { mPointer = ptr; }
    hidl_pointer(const hidl_pointer<T>& other) : hidl_pointer() { mPointer = other.mPointer; }
    hidl_pointer(hidl_pointer<T>&& other) noexcept : hidl_pointer() { *this = std::move(other); }

    hidl_pointer &operator=(const hidl_pointer<T>& other) {
        mPointer = other.mPointer;
        return *this;
    }
    hidl_pointer& operator=(hidl_pointer<T>&& other) noexcept {
        mPointer = other.mPointer;
        other.mPointer = nullptr;
        return *this;
    }
    hidl_pointer &operator=(T* ptr) {
        mPointer = ptr;
        return *this;
    }

    operator T*() const {
        return mPointer;
    }
    explicit operator void*() const { // requires explicit cast to avoid ambiguity
        return mPointer;
    }
    T& operator*() const {
        return *mPointer;
    }
    T* operator->() const {
        return mPointer;
    }
    T &operator[](size_t index) {
        return mPointer[index];
    }
    const T &operator[](size_t index) const {
        return mPointer[index];
    }

private:
    union {
        T* mPointer;
        uint64_t _pad;
    };
};

#define HAL_LIBRARY_PATH_SYSTEM_64BIT "/system/lib64/hw/"
#define HAL_LIBRARY_PATH_SYSTEM_EXT_64BIT "/system_ext/lib64/hw/"
#define HAL_LIBRARY_PATH_VENDOR_64BIT "/vendor/lib64/hw/"
#define HAL_LIBRARY_PATH_ODM_64BIT    "/odm/lib64/hw/"
#define HAL_LIBRARY_PATH_SYSTEM_32BIT "/system/lib/hw/"
#define HAL_LIBRARY_PATH_SYSTEM_EXT_32BIT "/system_ext/lib/hw/"
#define HAL_LIBRARY_PATH_VENDOR_32BIT "/vendor/lib/hw/"
#define HAL_LIBRARY_PATH_ODM_32BIT    "/odm/lib/hw/"

#if defined(__LP64__)
#define HAL_LIBRARY_PATH_SYSTEM HAL_LIBRARY_PATH_SYSTEM_64BIT
#define HAL_LIBRARY_PATH_SYSTEM_EXT HAL_LIBRARY_PATH_SYSTEM_EXT_64BIT
#define HAL_LIBRARY_PATH_VENDOR HAL_LIBRARY_PATH_VENDOR_64BIT
#define HAL_LIBRARY_PATH_ODM    HAL_LIBRARY_PATH_ODM_64BIT
#else
#define HAL_LIBRARY_PATH_SYSTEM HAL_LIBRARY_PATH_SYSTEM_32BIT
#define HAL_LIBRARY_PATH_SYSTEM_EXT HAL_LIBRARY_PATH_SYSTEM_EXT_32BIT
#define HAL_LIBRARY_PATH_VENDOR HAL_LIBRARY_PATH_VENDOR_32BIT
#define HAL_LIBRARY_PATH_ODM    HAL_LIBRARY_PATH_ODM_32BIT
#endif

// no requirements on types not used in scatter/gather
// no requirements on other libraries
#pragma clang diagnostic push
#pragma clang diagnostic ignored "-Wpadded"
#pragma clang diagnostic pop

} /* namespace details */

static const char *const kEmptyString = "";
struct hidl_string {
    hidl_string() : mBuffer(kEmptyString), mSize(0), mOwnsBuffer(false) {
        memset(mPad, 0, sizeof(mPad));
    }
    ~hidl_string() {
        clear();
    }

    // copy constructor.
    hidl_string(const hidl_string &other) {
        copyFrom(other.c_str(), other.size());
    }
    // copy from a C-style string. nullptr will create an empty string
    hidl_string(const char *s) : hidl_string() {
        if (s == nullptr) {
            return;
        }

        copyFrom(s, strlen(s));
    }
    // copy the first length characters from a C-style string.
    hidl_string(const char *s, size_t length) : hidl_string() {
        copyFrom(s, length);
    }
    // copy from an std::string.
    hidl_string(const std::string &s) {
        copyFrom(s.c_str(), s.size());
    }

    // move constructor.
    hidl_string(hidl_string&& other) noexcept : hidl_string() {
        moveFrom(std::forward<hidl_string>(other));
    }

    const char *c_str() const { return mBuffer; }
    size_t size() const { return mSize; }
    bool empty() const { return mSize == 0; }

    // copy assignment operator.
    hidl_string &operator=(const hidl_string &other) {
        if (this != &other) {
            clear();
            copyFrom(other.c_str(), other.size());
        }

        return *this;
    }
    // copy from a C-style string.
    hidl_string &operator=(const char *s) {
        clear();

        if (s == nullptr) {
            return *this;
        }

        copyFrom(s, strlen(s));
        return *this;
    }
    // copy from an std::string.
    hidl_string &operator=(const std::string &s) {
        clear();
        copyFrom(s.c_str(), s.size());
        return *this;
    }
    // move assignment operator.
    hidl_string &operator=(hidl_string &&other) noexcept {
        if (this != &other) {
            clear();
            moveFrom(std::forward<hidl_string>(other));
        }
        return *this;
    }
    // cast to std::string.
    operator std::string() const {
        return std::string(mBuffer, mSize);
    }


    void clear() {
        if (mOwnsBuffer && (mBuffer != kEmptyString)) {
            free(const_cast<char *>(static_cast<const char *>(mBuffer)));
        }

        mBuffer = kEmptyString;
        mSize = 0;
        mOwnsBuffer = false;
    }

    // Reference an external char array. Ownership is _not_ transferred.
    // Caller is responsible for ensuring that underlying memory is valid
    // for the lifetime of this hidl_string.
    //
    // size == strlen(data)
    void setToExternal(const char *data, size_t size) {
        if (size > UINT32_MAX) {
            std::cerr << "string size can't exceed 2^32 bytes: " << size;
            std::terminate();
        }

        // When the binder driver copies this data into its buffer, it must
        // have a zero byte there because the remote process will have a pointer
        // directly into the read-only binder buffer. If we manually copy the
        // data now to add a zero, then we lose the efficiency of this method.
        // Checking here (it's also checked in the parceling code later).
        assert(data[size] == '\0');

        clear();

        mBuffer = data;
        mSize = static_cast<uint32_t>(size);
        mOwnsBuffer = false;
    }

private:
    details::hidl_pointer<const char> mBuffer;
    uint32_t mSize;  // NOT including the terminating '\0'.
    bool mOwnsBuffer; // if true then mBuffer is a mutable char *
    uint8_t mPad[3];

    // copy from data with size. Assume that my memory is freed
    // (through clear(), for example)
    void copyFrom(const char *data, size_t size) {
        // assume my resources are freed.

        if (size >= UINT32_MAX) {
            std::cerr << "string size can't exceed 2^32 bytes: " << size;
            std::terminate();
        }

        if (size == 0) {
            mBuffer = kEmptyString;
            mSize = 0;
            mOwnsBuffer = false;
            return;
        }

        char *buf = (char *)malloc(size + 1);
        memcpy(buf, data, size);
        buf[size] = '\0';
        mBuffer = buf;

        mSize = static_cast<uint32_t>(size);
        mOwnsBuffer = true;
    }
    // move from another hidl_string
    void moveFrom(hidl_string &&other) {
        // assume my resources are freed.

        mBuffer = std::move(other.mBuffer);
        mSize = other.mSize;
        mOwnsBuffer = other.mOwnsBuffer;

        other.mOwnsBuffer = false;
        other.clear();
    }

public:
    // offsetof(hidl_string, mBuffer) exposed since mBuffer is private.
    static const size_t kOffsetOfBuffer;
};

// Use NOLINT to suppress missing parentheses warnings around OP.
#define HIDL_STRING_OPERATOR(OP)                                              \
    inline bool operator OP(const hidl_string& hs1, const hidl_string& hs2) { \
        return strcmp(hs1.c_str(), hs2.c_str()) OP 0; /* NOLINT */            \
    }                                                                         \
    inline bool operator OP(const hidl_string& hs, const char* s) {           \
        return strcmp(hs.c_str(), s) OP 0; /* NOLINT */                       \
    }                                                                         \
    inline bool operator OP(const char* s, const hidl_string& hs) {           \
        return strcmp(s, hs.c_str()) OP 0; /* NOLINT */                       \
    }

HIDL_STRING_OPERATOR(==)
HIDL_STRING_OPERATOR(!=)
HIDL_STRING_OPERATOR(<)
HIDL_STRING_OPERATOR(<=)
HIDL_STRING_OPERATOR(>)
HIDL_STRING_OPERATOR(>=)

#undef HIDL_STRING_OPERATOR

template<typename T>
struct hidl_vec {
    using value_type = T;

    hidl_vec() : mBuffer(nullptr), mSize(0), mOwnsBuffer(false) {

        memset(mPad, 0, sizeof(mPad));
    }

    hidl_vec(size_t size) : hidl_vec() { resize(size); }

    hidl_vec(const hidl_vec<T> &other) : hidl_vec() {
        *this = other;
    }

    hidl_vec(hidl_vec<T> &&other) noexcept : hidl_vec() {
        *this = std::move(other);
    }

    hidl_vec(const std::initializer_list<T> list) : hidl_vec() { *this = list; }

    hidl_vec(const std::vector<T> &other) : hidl_vec() {
        *this = other;
    }

    template <typename InputIterator,
              typename = typename std::enable_if<std::is_convertible<
                  typename std::iterator_traits<InputIterator>::iterator_category,
                  std::input_iterator_tag>::value>::type>
    hidl_vec(InputIterator first, InputIterator last) : hidl_vec() {
        auto size = std::distance(first, last);
        if (size > static_cast<int64_t>(UINT32_MAX)) {
            details::logAlwaysFatal("hidl_vec can't hold more than 2^32 elements.");
        }
        if (size < 0) {
            details::logAlwaysFatal("size can't be negative.");
        }
        mSize = static_cast<uint32_t>(size);
        mBuffer = new T[mSize]();
        mOwnsBuffer = true;

        size_t idx = 0;
        for (; first != last; ++first) {
            mBuffer[idx++] = static_cast<T>(*first);
        }
    }

    ~hidl_vec() {
        if (mOwnsBuffer) {
            delete[] mBuffer;
        }
        mBuffer = nullptr;
    }

    // Reference an existing array, optionally taking ownership. It is the
    // caller's responsibility to ensure that the underlying memory stays
    // valid for the lifetime of this hidl_vec.
    void setToExternal(T *data, size_t size, bool shouldOwn = false) {
        if (mOwnsBuffer) {
            delete [] mBuffer;
        }
        mBuffer = data;
        if (size > UINT32_MAX) {
            details::logAlwaysFatal("external vector size exceeds 2^32 elements.");
        }
        mSize = static_cast<uint32_t>(size);
        mOwnsBuffer = shouldOwn;
    }

    T *data() {
        return mBuffer;
    }

    const T *data() const {
        return mBuffer;
    }

    T *releaseData() {
        if (!mOwnsBuffer && mBuffer != nullptr) {
            resize(mSize);
        }
        mOwnsBuffer = false;
        return mBuffer;
    }

    hidl_vec &operator=(hidl_vec &&other) noexcept {
        if (mOwnsBuffer) {
            delete[] mBuffer;
        }
        mBuffer = other.mBuffer;
        mSize = other.mSize;
        mOwnsBuffer = other.mOwnsBuffer;
        other.mOwnsBuffer = false;
        return *this;
    }

    hidl_vec &operator=(const hidl_vec &other) {
        if (this != &other) {
            if (mOwnsBuffer) {
                delete[] mBuffer;
            }
            copyFrom(other, other.mSize);
        }

        return *this;
    }

    // copy from an std::vector.
    hidl_vec &operator=(const std::vector<T> &other) {
        if (mOwnsBuffer) {
            delete[] mBuffer;
        }
        copyFrom(other, other.size());
        return *this;
    }

    hidl_vec& operator=(const std::initializer_list<T> list) {
        if (list.size() > UINT32_MAX) {
            details::logAlwaysFatal("hidl_vec can't hold more than 2^32 elements.");
        }
        if (mOwnsBuffer) {
            delete[] mBuffer;
        }
        mSize = static_cast<uint32_t>(list.size());
        mBuffer = new T[mSize]();
        mOwnsBuffer = true;

        size_t idx = 0;
        for (auto it = list.begin(); it != list.end(); ++it) {
            mBuffer[idx++] = *it;
        }
        return *this;
    }

    // cast to an std::vector.
    operator std::vector<T>() const {
        std::vector<T> v(mSize);
        for (size_t i = 0; i < mSize; ++i) {
            v[i] = mBuffer[i];
        }
        return v;
    }

    // equality check, assuming that T::operator== is defined.
    bool operator==(const hidl_vec &other) const {
        if (mSize != other.size()) {
            return false;
        }
        for (size_t i = 0; i < mSize; ++i) {
            if (!(mBuffer[i] == other.mBuffer[i])) {
                return false;
            }
        }
        return true;
    }

    // inequality check, assuming that T::operator== is defined.
    inline bool operator!=(const hidl_vec &other) const {
        return !((*this) == other);
    }

    size_t size() const {
        return mSize;
    }

    T &operator[](size_t index) {
        return mBuffer[index];
    }

    const T &operator[](size_t index) const {
        return mBuffer[index];
    }

    // Copies over old elements fitting in new size. Value initializes the rest.
    void resize(size_t size) {
        if (size > UINT32_MAX) {
            details::logAlwaysFatal("hidl_vec can't hold more than 2^32 elements.");
        }
        T* newBuffer = new T[size]();

        for (size_t i = 0; i < std::min(static_cast<uint32_t>(size), mSize); ++i) {
            newBuffer[i] = std::move(mBuffer[i]);
        }

        if (mOwnsBuffer) {
            delete[] mBuffer;
        }
        mBuffer = newBuffer;

        mSize = static_cast<uint32_t>(size);
        mOwnsBuffer = true;
    }

private:
    // Define std interator interface for walking the array contents
    template<bool is_const>
    class iter {
    public:
        using iterator_category = std::random_access_iterator_tag;
        using value_type = T;
        using difference_type = ptrdiff_t;
        using pointer = std::conditional_t<is_const, const T *, T *>;
        using reference = std::conditional_t<is_const, const T &, T &>;
        iter(pointer ptr) : mPtr(ptr) { }
        inline iter &operator++()    { mPtr++; return *this; }
        inline iter  operator++(int) { iter i = *this; mPtr++; return i; }
        inline iter &operator--()    { mPtr--; return *this; }
        inline iter  operator--(int) { iter i = *this; mPtr--; return i; }
        inline friend iter operator+(difference_type n, const iter &it) { return it.mPtr + n; }
        inline iter  operator+(difference_type n) const { return mPtr + n; }
        inline iter  operator-(difference_type n) const { return mPtr - n; }
        inline difference_type operator-(const iter &other) const { return mPtr - other.mPtr; }
        inline iter &operator+=(difference_type n) { mPtr += n; return *this; }
        inline iter &operator-=(difference_type n) { mPtr -= n; return *this; }
        inline reference operator*() const { return *mPtr; }
        inline pointer operator->() const  { return mPtr; }
        inline bool operator==(const iter &rhs) const { return mPtr == rhs.mPtr; }
        inline bool operator!=(const iter &rhs) const { return mPtr != rhs.mPtr; }
        inline bool operator< (const iter &rhs) const { return mPtr <  rhs.mPtr; }
        inline bool operator> (const iter &rhs) const { return mPtr >  rhs.mPtr; }
        inline bool operator<=(const iter &rhs) const { return mPtr <= rhs.mPtr; }
        inline bool operator>=(const iter &rhs) const { return mPtr >= rhs.mPtr; }
        inline reference operator[](size_t n) const { return mPtr[n]; }
    private:
        pointer mPtr;
    };
public:
    using iterator       = iter<false /* is_const */>;
    using const_iterator = iter<true  /* is_const */>;

    iterator begin() { return data(); }
    iterator end() { return data()+mSize; }
    const_iterator begin() const { return data(); }
    const_iterator end() const { return data()+mSize; }
    iterator find(const T& v) { return std::find(begin(), end(), v); }
    const_iterator find(const T& v) const { return std::find(begin(), end(), v); }
    bool contains(const T& v) const { return find(v) != end(); }

  private:
    details::hidl_pointer<T> mBuffer;
    uint32_t mSize;
    bool mOwnsBuffer;
    uint8_t mPad[3];

    // copy from an array-like object, assuming my resources are freed.
    template <typename Array>
    void copyFrom(const Array &data, size_t size) {
        mSize = static_cast<uint32_t>(size);
        mOwnsBuffer = true;
        if (mSize > 0) {
            mBuffer = new T[size]();
            for (size_t i = 0; i < size; ++i) {
                mBuffer[i] = data[i];
            }
        } else {
            mBuffer = nullptr;
        }
    }
  public:
    // offsetof(hidl_string, mBuffer) exposed since mBuffer is private.
    static const size_t kOffsetOfBuffer;
};

template <typename T>
const size_t hidl_vec<T>::kOffsetOfBuffer = offsetof(hidl_vec<T>, mBuffer);

////////////////////////////////////////////////////////////////////////////////

namespace details {

    template<size_t SIZE1, size_t... SIZES>
    struct product {
        static constexpr size_t value = SIZE1 * product<SIZES...>::value;
    };

    template<size_t SIZE1>
    struct product<SIZE1> {
        static constexpr size_t value = SIZE1;
    };

    template<typename T, size_t SIZE1, size_t... SIZES>
    struct std_array {
        using type = std::array<typename std_array<T, SIZES...>::type, SIZE1>;
    };

    template<typename T, size_t SIZE1>
    struct std_array<T, SIZE1> {
        using type = std::array<T, SIZE1>;
    };

    template<typename T, size_t SIZE1, size_t... SIZES>
    struct accessor {

        using std_array_type = typename std_array<T, SIZE1, SIZES...>::type;

        explicit accessor(T *base)
            : mBase(base) {
        }

        accessor<T, SIZES...> operator[](size_t index) {
            return accessor<T, SIZES...>(
                    &mBase[index * product<SIZES...>::value]);
        }

        accessor &operator=(const std_array_type &other) {
            for (size_t i = 0; i < SIZE1; ++i) {
                (*this)[i] = other[i];
            }
            return *this;
        }

    private:
        T *mBase;
    };

    template<typename T, size_t SIZE1>
    struct accessor<T, SIZE1> {

        using std_array_type = typename std_array<T, SIZE1>::type;

        explicit accessor(T *base)
            : mBase(base) {
        }

        T &operator[](size_t index) {
            return mBase[index];
        }

        accessor &operator=(const std_array_type &other) {
            for (size_t i = 0; i < SIZE1; ++i) {
                (*this)[i] = other[i];
            }
            return *this;
        }

    private:
        T *mBase;
    };

    template<typename T, size_t SIZE1, size_t... SIZES>
    struct const_accessor {

        using std_array_type = typename std_array<T, SIZE1, SIZES...>::type;

        explicit const_accessor(const T *base)
            : mBase(base) {
        }

        const_accessor<T, SIZES...> operator[](size_t index) const {
            return const_accessor<T, SIZES...>(
                    &mBase[index * product<SIZES...>::value]);
        }

        operator std_array_type() {
            std_array_type array;
            for (size_t i = 0; i < SIZE1; ++i) {
                array[i] = (*this)[i];
            }
            return array;
        }

    private:
        const T *mBase;
    };

    template<typename T, size_t SIZE1>
    struct const_accessor<T, SIZE1> {

        using std_array_type = typename std_array<T, SIZE1>::type;

        explicit const_accessor(const T *base)
            : mBase(base) {
        }

        const T &operator[](size_t index) const {
            return mBase[index];
        }

        operator std_array_type() {
            std_array_type array;
            for (size_t i = 0; i < SIZE1; ++i) {
                array[i] = (*this)[i];
            }
            return array;
        }

    private:
        const T *mBase;
    };

}  // namespace details

////////////////////////////////////////////////////////////////////////////////

// A multidimensional array of T's. Assumes that T::operator=(const T &) is defined.
template<typename T, size_t SIZE1, size_t... SIZES>
struct hidl_array {

    using std_array_type = typename details::std_array<T, SIZE1, SIZES...>::type;

    hidl_array() = default;
    hidl_array(const hidl_array&) noexcept = default;
    hidl_array(hidl_array&&) noexcept = default;

    // Copies the data from source, using T::operator=(const T &).
    hidl_array(const T *source) {
        for (size_t i = 0; i < elementCount(); ++i) {
            mBuffer[i] = source[i];
        }
    }

    // Copies the data from the given std::array, using T::operator=(const T &).
    hidl_array(const std_array_type &array) {
        details::accessor<T, SIZE1, SIZES...> modifier(mBuffer);
        modifier = array;
    }

    hidl_array& operator=(const hidl_array&) noexcept = default;
    hidl_array& operator=(hidl_array&&) noexcept = default;

    T *data() { return mBuffer; }
    const T *data() const { return mBuffer; }

    details::accessor<T, SIZES...> operator[](size_t index) {
        return details::accessor<T, SIZES...>(
                &mBuffer[index * details::product<SIZES...>::value]);
    }

    details::const_accessor<T, SIZES...> operator[](size_t index) const {
        return details::const_accessor<T, SIZES...>(
                &mBuffer[index * details::product<SIZES...>::value]);
    }

    // equality check, assuming that T::operator== is defined.
    bool operator==(const hidl_array &other) const {
        for (size_t i = 0; i < elementCount(); ++i) {
            if (!(mBuffer[i] == other.mBuffer[i])) {
                return false;
            }
        }
        return true;
    }

    inline bool operator!=(const hidl_array &other) const {
        return !((*this) == other);
    }

    using size_tuple_type = std::tuple<decltype(SIZE1), decltype(SIZES)...>;

    static constexpr size_tuple_type size() {
        return std::make_tuple(SIZE1, SIZES...);
    }

    static constexpr size_t elementCount() {
        return details::product<SIZE1, SIZES...>::value;
    }

    operator std_array_type() const {
        return details::const_accessor<T, SIZE1, SIZES...>(mBuffer);
    }

private:
    T mBuffer[elementCount()];
};

// An array of T's. Assumes that T::operator=(const T &) is defined.
template<typename T, size_t SIZE1>
struct hidl_array<T, SIZE1> {
    using value_type = T;
    using std_array_type = typename details::std_array<T, SIZE1>::type;

    hidl_array() = default;
    hidl_array(const hidl_array&) noexcept = default;
    hidl_array(hidl_array&&) noexcept = default;

    // Copies the data from source, using T::operator=(const T &).
    hidl_array(const T *source) {
        for (size_t i = 0; i < elementCount(); ++i) {
            mBuffer[i] = source[i];
        }
    }

    // Copies the data from the given std::array, using T::operator=(const T &).
    hidl_array(const std_array_type &array) : hidl_array(array.data()) {}

    hidl_array& operator=(const hidl_array&) noexcept = default;
    hidl_array& operator=(hidl_array&&) noexcept = default;

    T *data() { return mBuffer; }
    const T *data() const { return mBuffer; }

    T &operator[](size_t index) {
        return mBuffer[index];
    }

    const T &operator[](size_t index) const {
        return mBuffer[index];
    }

    // equality check, assuming that T::operator== is defined.
    bool operator==(const hidl_array &other) const {
        for (size_t i = 0; i < elementCount(); ++i) {
            if (!(mBuffer[i] == other.mBuffer[i])) {
                return false;
            }
        }
        return true;
    }

    inline bool operator!=(const hidl_array &other) const {
        return !((*this) == other);
    }

    static constexpr size_t size() { return SIZE1; }
    static constexpr size_t elementCount() { return SIZE1; }

    // Copies the data to an std::array, using T::operator=(T).
    operator std_array_type() const {
        std_array_type array;
        for (size_t i = 0; i < SIZE1; ++i) {
            array[i] = mBuffer[i];
        }
        return array;
    }

private:
    T mBuffer[SIZE1];
};

// ----------------------------------------------------------------------
// Version functions
struct hidl_version {
public:
    constexpr hidl_version(uint16_t major, uint16_t minor) : mMajor(major), mMinor(minor) {
    }

    bool operator==(const hidl_version& other) const {
        return (mMajor == other.get_major() && mMinor == other.get_minor());
    }

    bool operator!=(const hidl_version& other) const {
        return !(*this == other);
    }

    bool operator<(const hidl_version& other) const {
        return (mMajor < other.get_major() ||
                (mMajor == other.get_major() && mMinor < other.get_minor()));
    }

    bool operator>(const hidl_version& other) const {
        return other < *this;
    }

    bool operator<=(const hidl_version& other) const {
        return !(*this > other);
    }

    bool operator>=(const hidl_version& other) const {
        return !(*this < other);
    }

    constexpr uint16_t get_major() const { return mMajor; }
    constexpr uint16_t get_minor() const { return mMinor; }

private:
    uint16_t mMajor;
    uint16_t mMinor;
};

inline android::hardware::hidl_version make_hidl_version(uint16_t major, uint16_t minor) {
    return hidl_version(major,minor);
}

///////////////////// toString functions

std::string toString(const void *t);

// toString alias for numeric types
template<typename T, typename = typename std::enable_if<std::is_arithmetic<T>::value, T>::type>
inline std::string toString(T t) {
    return std::to_string(t);
}

namespace details {

template<typename T, typename = typename std::enable_if<std::is_arithmetic<T>::value, T>::type>
inline std::string toHexString(T t, bool prefix = true) {
    std::ostringstream os;
    if (prefix) { os << std::showbase; }
    os << std::hex << t;
    return os.str();
}

template<>
inline std::string toHexString(uint8_t t, bool prefix) {
    return toHexString(static_cast<int32_t>(t), prefix);
}

template<>
inline std::string toHexString(int8_t t, bool prefix) {
    return toHexString(static_cast<int32_t>(t), prefix);
}

template<typename Array>
std::string arrayToString(const Array &a, size_t size);

template<size_t SIZE1>
std::string arraySizeToString() {
    return std::string{"["} + toString(SIZE1) + "]";
}

template<size_t SIZE1, size_t SIZE2, size_t... SIZES>
std::string arraySizeToString() {
    return std::string{"["} + toString(SIZE1) + "]" + arraySizeToString<SIZE2, SIZES...>();
}

template<typename T, size_t SIZE1>
std::string toString(details::const_accessor<T, SIZE1> a) {
    return arrayToString(a, SIZE1);
}

template<typename Array>
std::string arrayToString(const Array &a, size_t size) {
    using android::hardware::toString;
    std::string os;
    os += "{";
    for (size_t i = 0; i < size; ++i) {
        if (i > 0) {
            os += ", ";
        }
        os += toString(a[i]);
    }
    os += "}";
    return os;
}

template<typename T, size_t SIZE1, size_t SIZE2, size_t... SIZES>
std::string toString(details::const_accessor<T, SIZE1, SIZE2, SIZES...> a) {
    return arrayToString(a, SIZE1);
}

}  //namespace details

inline std::string toString(const void *t) {
    return details::toHexString(reinterpret_cast<uintptr_t>(t));
}

// debug string dump. There will be quotes around the string!
inline std::string toString(const hidl_string &hs) {
    return std::string{"\""} + hs.c_str() + "\"";
}

// debug string dump, assuming that toString(T) is defined.
template<typename T>
std::string toString(const hidl_vec<T> &a) {
    std::string os;
    os += "[" + toString(a.size()) + "]";
    os += details::arrayToString(a, a.size());
    return os;
}

template<typename T, size_t SIZE1>
std::string toString(const hidl_array<T, SIZE1> &a) {
    return details::arraySizeToString<SIZE1>()
            + details::toString(details::const_accessor<T, SIZE1>(a.data()));
}

template<typename T, size_t SIZE1, size_t SIZE2, size_t... SIZES>
std::string toString(const hidl_array<T, SIZE1, SIZE2, SIZES...> &a) {
    return details::arraySizeToString<SIZE1, SIZE2, SIZES...>()
            + details::toString(details::const_accessor<T, SIZE1, SIZE2, SIZES...>(a.data()));
}

namespace details {
// Never instantiated. Used as a placeholder for template variables.
template <typename T>
struct hidl_invalid_type;

// HIDL generates specializations of this for enums. See hidl_enum_range.
template <typename T, typename = std::enable_if_t<std::is_enum<T>::value>>
constexpr hidl_invalid_type<T> hidl_enum_values;
}  // namespace details

/**
 * Every HIDL generated enum supports this function.
 * E.x.: for(const auto v : hidl_enum_range<Enum>) { ... }
 */
template <typename T, typename = std::enable_if_t<std::is_enum<T>::value>>
struct hidl_enum_range {
    // Container-like associated type.
    using value_type = T;

    constexpr auto begin() const { return std::begin(details::hidl_enum_values<T>); }
    constexpr auto cbegin() const { return begin(); }
    constexpr auto rbegin() const { return std::rbegin(details::hidl_enum_values<T>); }
    constexpr auto crbegin() const { return rbegin(); }
    constexpr auto end() const { return std::end(details::hidl_enum_values<T>); }
    constexpr auto cend() const { return end(); }
    constexpr auto rend() const { return std::rend(details::hidl_enum_values<T>); }
    constexpr auto crend() const { return rend(); }
};

template <typename T, typename = std::enable_if_t<std::is_enum<T>::value>>
struct hidl_enum_iterator {
    static_assert(!std::is_enum<T>::value,
                  "b/78573628: hidl_enum_iterator was renamed to hidl_enum_range because it is not "
                  "actually an iterator. Please use that type instead.");
};

/**
 * Bitfields in HIDL are the underlying type of the enumeration.
 */
template <typename Enum>
using hidl_bitfield = typename std::underlying_type<Enum>::type;

}  // namespace hardware
}  // namespace android


#endif  // ANDROID_HIDL_SUPPORT_H
