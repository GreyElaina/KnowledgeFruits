<template>
    <div>
        <el-button @click="change">
            <rotate v-if="hasIcon" ref="child"><span @click="change"><slot></slot></span><i @click="change" :class="iconClass"></i></rotate>
            <span v-else><slot></slot></span>
        </el-button>
    </div>
</template>

<script>
import RotateComponent from "./rotate.vue"

export default {
    props: {
        hasIcon: Boolean,
        iconClass: String
    },
    data: {},
    components:{
        rotate: RotateComponent
    },
    methods: {
        change(){
            this.$refs.child.click()
        }
    }
}
</script>