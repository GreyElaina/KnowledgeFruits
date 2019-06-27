<template>
    <div :class="{rotate: !rotated, rotate1: rotated}" @click="click()"><slot></slot></div>
</template>
<style>
.rotate > *{
    transform-origin:center center;
    transform: rotate(180deg);
    -webkit-transform: rotate(180deg);
    -moz-transform: rotate(180deg);
    -ms-transform: rotate(180deg);
    -o-transform: rotate(180deg);
    transition: transform 0.2s;
    -moz-transition: -moz-transform 0.2s; 
    -moz-transition: -moz-transform 0.2s; 
    -o-transition: -o-transform 0.2s; 
    -ms-transition: -ms-transform 0.2s; 
}

.rotate1 > *{
    transform-origin:center center;
    transform: rotate(0deg);
    -webkit-transform: rotate(0deg);
    -moz-transform: rotate(deg);
    -ms-transform: rotate(0deg);
    -o-transform: rotate(0deg);
    transition: transform 0.2s; 
    -moz-transition: -moz-transform 0.2s; 
    -moz-transition: -moz-transform 0.2s; 
    -o-transition: -o-transform 0.2s; 
    -ms-transition: -ms-transform 0.2s; 
}
</style>
<script>
export default {
    data(){
        return {
            rotated: true
        }
    },
    methods: {
        click(){
            this.rotated = !this.rotated
        }
    }
}
</script>